#include "node.h"
#include "node_buffer.h"
#include "node_object_wrap.h"
#include "v8.h"

#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"

#include <assert.h>
#include <stdlib.h>

namespace splittls {

using namespace node;
using namespace v8;

static const RSA_METHOD* rsa_eay;

class Engine : public ObjectWrap {
 public:
  static Handle<Value> New(const Arguments& args) {
    HandleScope scope;

    BIO* bio = BIO_new(BIO_s_mem());
    assert(bio != NULL);

    char* key_data = Buffer::Data(args[0]);
    size_t key_len = Buffer::Length(args[0]);
    int r = BIO_write(bio, key_data, key_len);
    assert(r == (int) key_len);

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free_all(bio);
    if (pkey == NULL) {
      return ThrowException(Exception::Error(String::New(
          "PEM read BIO failure")));
    }

    Engine* e = new Engine(pkey);
    e->Wrap(args.This());

    return scope.Close(args.This());
  }

  static Handle<Value> ModExp(const Arguments& args) {
    HandleScope scope;

    Engine* e = ObjectWrap::Unwrap<Engine>(args.This());

    char* data = Buffer::Data(args[0]);
    size_t len = Buffer::Length(args[0]);
    BIGNUM* I = BN_bin2bn(reinterpret_cast<unsigned char*>(data), len, e->i_);
    assert(I == e->i_);

    if (!rsa_eay->rsa_mod_exp(e->r_, I, e->pkey_->pkey.rsa, e->ctx_)) {
      return ThrowException(Exception::Error(String::New(
          "Mod exp failed")));
    }

    char* hex = BN_bn2hex(e->r_);
    assert(hex != NULL);

    Local<String> hstr = String::New(hex);
    free(hex);
    return scope.Close(hstr);
  }

 protected:
  Engine(EVP_PKEY* pkey) : pkey_(pkey) {
    ctx_ = BN_CTX_new();
    assert(ctx_ != NULL);

    BN_CTX_start(ctx_);
    r_ = BN_CTX_get(ctx_);
    i_ = BN_CTX_get(ctx_);
    assert(r_ != NULL && i_ != NULL);

    assert(ctx_ != NULL);
  }

  ~Engine() {
    BN_CTX_end(ctx_);
    BN_CTX_free(ctx_);
    EVP_PKEY_free(pkey_);

    pkey_ = NULL;
    ctx_ = NULL;
    r_ = NULL;
    i_ = NULL;
  }

  static void FreeHex(char* data, void* hint) {
    free(data);
  }

  BIGNUM* r_;
  BIGNUM* i_;
  EVP_PKEY* pkey_;
  BN_CTX* ctx_;
};

static void Init(Handle<Object> target) {
  HandleScope scope;

  // Init OpenSSL
  OpenSSL_add_all_algorithms();
  RAND_poll();
  rsa_eay = RSA_PKCS1_SSLeay();

  Local<FunctionTemplate> t = FunctionTemplate::New(Engine::New);

  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("Engine"));

  NODE_SET_PROTOTYPE_METHOD(t, "modExp", Engine::ModExp);

  target->Set(String::NewSymbol("Engine"), t->GetFunction());
}

}  // namespace splittls

NODE_MODULE(splittls_binding, splittls::Init);
