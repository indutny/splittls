#include "openssl/engine.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"

#include "common.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>


#define STLS_VERSION 1
#define STLS_ENGINE_CMD_IGNORE 0x1000
#define STLS_ENGINE_CMD_SOCK   0x1001

typedef enum stls_msg_type_e stls_msg_type_t;
typedef struct stls_msg_hdr_s stls_msg_hdr_t;
typedef struct stls_msg_mod_exp_s stls_msg_mod_exp_t;
typedef struct stls_msg_mod_exp_reply_s stls_msg_mod_exp_reply_t;
typedef struct stls_s stls_t;

enum stls_msg_type_e {
  kSTLSMsgModExp       = 0x1,
  kSTLSMsgModExpReply  = 0x2
};

struct stls_msg_hdr_s {
  uint16_t version;
  uint16_t type;
  uint32_t size;
};

struct stls_msg_mod_exp_s {
  /* 16384 bits should be enough */
  unsigned char num[2048];
};

struct stls_msg_mod_exp_reply_s {
  unsigned char num[1];
};

struct stls_s {
  int channel;
  char* channel_path;
};

static pthread_once_t stls_st_once = PTHREAD_ONCE_INIT;
static pthread_key_t stls_st_key;

static stls_t* stls_get();


static int stls_lazy_connect(stls_t* stls) {
  int r;
  int fd;
  struct sockaddr_un addr;
  struct timeval tv;

  if (stls->channel_path == NULL)
    return -1;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    return -1;

  /* Wait two seconds for reply */
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  r = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  if (r != 0)
    goto fatal;

  r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  if (r != 0)
    goto fatal;

  memset(&addr, 0, sizeof(addr));
  strncpy(addr.sun_path, stls->channel_path, sizeof(addr.sun_path));
  addr.sun_family = AF_UNIX;

  r = connect(fd, (struct sockaddr*) &addr, sizeof(addr));
  if (r != 0)
    goto fatal;

  stls->channel = fd;

  return 0;

fatal:
  close(fd);
  return r;
}


static void stls_handle_error(stls_t* stls, int err) {
  close(stls->channel);
  stls->channel = -1;
}


static int stls_send(stls_t* stls, struct iovec* iov, int iovcnt) {
  int r;
  size_t left;

  /* Can't send after disconnect */
  if (stls->channel == -1)
    return -1;

  left = 0;
  for (r = 0; r < iovcnt; r++)
    left += iov[r].iov_len;

  while (left > 0) {
    do
      r = writev(stls->channel, iov, iovcnt);
    while (r == -1 && errno == EINTR);

    if (r == -1)
      goto fatal;

    left -= r;
    if (left == 0)
      break;

    /* Shift buffers */
    while (r > 0) {
      size_t avail;

      avail = iov[0].iov_len;
      if (avail > (size_t) r) {
        /* Shift */
        iov[0].iov_base += r;
        iov[0].iov_len -= r;
        r = 0;
      } else {
        /* Skip */
        iov++;
        iovcnt--;
        r -= avail;
      }
    }
  }

  return 0;

fatal:
  stls_handle_error(stls, errno);
  return r;
}


static int stls_recv(stls_t* stls, void* buf, int size) {
  int r;
  char* ptr;

  /* Can't receive after disconnect */
  if (stls->channel == -1)
    return -1;

  ptr = (char*) buf;
  while (size > 0) {
    do
      r = read(stls->channel, buf, size);
    while (r == -1 && errno == EINTR);
    if (r == -1)
      goto fatal;

    /* EOF may be? */
    if (r == 0) {
      r = -1;
      goto fatal;
    }

    buf += r;
    size -= r;
  }

  return 0;

fatal:
  stls_handle_error(stls, errno);
  return r;
}


static int stls_query(stls_t* stls,
                      stls_msg_type_t type,
                      uint32_t size,
                      void* body,
                      stls_msg_hdr_t* resp,
                      void** resp_body) {
  stls_msg_hdr_t hdr;
  struct iovec iov[2];
  int r;
  int tries;

  hdr.version = htons(STLS_VERSION);
  hdr.type = htons(type);
  hdr.size = htonl(size);

  /*
   * Try sending a couple of times, the connection could be broken at start,
   * and we won't notice it until `stls_send()` call.
   */
  tries = 0;
  do {
    r = stls_lazy_connect(stls);
    if (r != 0)
      continue;

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = body;
    iov[1].iov_len = size;

    r = stls_send(stls, iov, ARRAY_SIZE(iov));
    if (r != 0)
      continue;

    r = stls_recv(stls, resp, sizeof(*resp));
    if (r != 0)
      continue;
  } while (r != 0 && ++tries < 2);
  if (r != 0)
    return r;

  resp->version = ntohs(resp->version);
  resp->type = ntohs(resp->type);
  resp->size = ntohl(resp->size);

  *resp_body = malloc(resp->size);
  if (*resp_body == NULL)
    return -1;

  r = stls_recv(stls, *resp_body, resp->size);
  if (r != 0) {
    free(*resp_body);
    *resp_body = NULL;
  }
  return r;
}


static int stls_rsa_init(RSA* rsa) {
  /* Blinding will be performed on backend */
  rsa->flags |= RSA_FLAG_NO_BLINDING;
  return 1;
}


static int stls_rsa_mod_exp(BIGNUM* r0,
                            const BIGNUM* I,
                            RSA* rsa,
                            BN_CTX* ctx) {
  stls_msg_mod_exp_t body;
  int size;
  int r;
  stls_msg_hdr_t reply;
  stls_msg_mod_exp_reply_t* reply_body;
  stls_t* st;

  st = stls_get();

  size = BN_num_bytes(I);
  assert(size <= (int) sizeof(body.num));
  BN_bn2bin(I, body.num);

  if (stls_query(st,
                 kSTLSMsgModExp,
                 size,
                 &body,
                 &reply,
                 (void**) &reply_body) != 0) {
    return 0;
  }

  r = 0;

  /* Invalid message */
  if (reply.type != kSTLSMsgModExpReply)
    goto done;

  /* Parse reply */
  if (BN_bin2bn(reply_body->num, reply.size, r0) == NULL)
    goto done;

  r = 1;

done:
  free(reply_body);
  reply_body = NULL;
  return 1;
}


static RSA_METHOD stls_rsa = {
  .name = "SplitTLS RSA",
  .init = stls_rsa_init,
  .rsa_mod_exp = stls_rsa_mod_exp
};


static int stls_init(ENGINE* e) {
  return 1;
}


static int stls_finish(ENGINE* e) {
  int r;
  stls_t* st;

  st = stls_get();
  close(st->channel);
  st->channel = -1;
  free(st->channel_path);
  st->channel_path = NULL;
  free(st);

  r = pthread_setspecific(stls_st_key, NULL);
  assert(r == 0);

  return 1;
}


static int stls_ctrl(ENGINE *e,
                     int cmd,
                     long i,
                     void* p,
                     void (*f)(void)) {
  switch (cmd) {
    case ENGINE_CTRL_HAS_CTRL_FUNCTION:
      return 1;
    case ENGINE_CTRL_GET_CMD_FLAGS:
      return ENGINE_CMD_FLAG_STRING;
    case ENGINE_CTRL_GET_CMD_FROM_NAME:
      if (strncmp((char*) p, "STLS_SOCK", 9) != 0)
        return STLS_ENGINE_CMD_IGNORE;

      return STLS_ENGINE_CMD_SOCK;
    case STLS_ENGINE_CMD_IGNORE:
      return 1;
    case STLS_ENGINE_CMD_SOCK:
      stls_get()->channel_path = (char*) p;
      return 1;
    default:
      return 0;
  }
}


static int stls_bind_fn(ENGINE* e, const char* id) {
  stls_t* st;
  const RSA_METHOD* rsa_eay;

  if (id != NULL && strcmp(id, "splittls") != 0)
    return 0;

  st = stls_get();

  if (!ENGINE_set_id(e, "splittls") ||
      !ENGINE_set_name(e, "SplitTLS") ||
      !ENGINE_set_RSA(e, &stls_rsa) ||
      !ENGINE_set_init_function(e, stls_init) ||
      !ENGINE_set_finish_function(e, stls_finish) ||
      !ENGINE_set_ctrl_function(e, stls_ctrl)) {
    return 0;
  }

  /* Copy default, required methods */
  rsa_eay = RSA_PKCS1_SSLeay();
  stls_rsa.rsa_pub_enc = rsa_eay->rsa_pub_enc;
  stls_rsa.rsa_pub_dec = rsa_eay->rsa_pub_dec;
  stls_rsa.rsa_priv_enc = rsa_eay->rsa_priv_enc;
  stls_rsa.rsa_priv_dec = rsa_eay->rsa_priv_dec;
  stls_rsa.bn_mod_exp = rsa_eay->bn_mod_exp;

  return 1;
}


static void stls_once_init() {
  int r;

  r = pthread_key_create(&stls_st_key, free);
  assert(r == 0);
}


stls_t* stls_get() {
  int r;
  stls_t* st;

  r = pthread_once(&stls_st_once, stls_once_init);
  assert(r == 0);

  st = pthread_getspecific(stls_st_key);
  if (st != NULL)
    return st;

  st = calloc(1, sizeof(*st));
  assert(st != NULL);

  st->channel_path = strdup(getenv("STLS_SOCKET"));
  st->channel = -1;

  r = pthread_setspecific(stls_st_key, st);
  assert(r == 0);

  return st;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(stls_bind_fn)
