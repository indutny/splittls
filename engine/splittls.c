#include "openssl/engine.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"

#include "common.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>


#define STLS_VERSION 1

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
  const char* channel_path;
};

static stls_t stls_state;


static int stls_lazy_connect(stls_t* stls) {
  int r;
  struct sockaddr_un addr;

  if (stls_state.channel != -1)
    return 0;

  stls_state.channel = socket(AF_UNIX, SOCK_STREAM, 0);
  if (stls_state.channel == -1)
    return -1;

  memset(&addr, 0, sizeof(addr));
  strncpy(addr.sun_path, stls_state.channel_path, sizeof(addr.sun_path));
  addr.sun_family = AF_UNIX;

  r = connect(stls_state.channel, (struct sockaddr*) &addr, sizeof(addr));
  if (r != 0) {
    close(stls_state.channel);
    stls_state.channel = -1;
  }

  return r;
}


static void stls_handle_error(stls_t* stls, int err) {
  close(stls_state.channel);
  stls_state.channel = -1;
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

  r = stls_lazy_connect(stls);
  if (r != 0)
    return r;

  hdr.version = htons(STLS_VERSION);
  hdr.type = htons(type);
  hdr.size = htonl(size);

  iov[0].iov_base = &hdr;
  iov[0].iov_len = sizeof(hdr);
  iov[1].iov_base = body;
  iov[1].iov_len = size;

  r = stls_send(stls, iov, ARRAY_SIZE(iov));
  if (r != 0)
    return r;

  r = stls_recv(stls, resp, sizeof(*resp));
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

  size = BN_num_bytes(I);
  assert(size <= (int) sizeof(body.num));
  BN_bn2bin(I, body.num);

  if (stls_query(&stls_state,
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
  if (stls_state.channel_path != NULL)
    return 1;

  stls_state.channel_path = getenv("STLS_SOCKET");
  if (stls_state.channel_path == NULL)
    return 0;

  stls_state.channel = -1;

  return 1;
}


static int stls_finish(ENGINE* e) {
  if (stls_state.channel_path == NULL)
    return 1;

  close(stls_state.channel);
  stls_state.channel = -1;
  stls_state.channel_path = NULL;

  return 1;
}


static int stls_bind_fn(ENGINE* e, const char* id) {
  const RSA_METHOD* rsa_eay;

  if (id != NULL && strcmp(id, "splittls") != 0)
    return 0;
  if (!ENGINE_set_id(e, "splittls") ||
      !ENGINE_set_name(e, "SplitTLS") ||
      !ENGINE_set_RSA(e, &stls_rsa) ||
      !ENGINE_set_init_function(e, stls_init) ||
      !ENGINE_set_finish_function(e, stls_finish)) {
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

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(stls_bind_fn)
