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

    // We use RSA_private_decrypt just to perform the blinding that is turned
    // off on the frontend.
    int r = RSA_private_decrypt(len,
                                reinterpret_cast<const unsigned char*>(data),
                                e->out_,
                                e->pkey_->pkey.rsa,
                                RSA_NO_PADDING);
    if (r <= 0) {
      return ThrowException(Exception::Error(String::New(
          "RSA mod exp failed")));
    }

    return scope.Close(
        Buffer::New(reinterpret_cast<char*>(e->out_), r)->handle_);
  }

 protected:
  Engine(EVP_PKEY* pkey) : pkey_(pkey) {
    out_ = new unsigned char[RSA_size(pkey->pkey.rsa)];
  }

  ~Engine() {
    EVP_PKEY_free(pkey_);
    delete[] out_;

    pkey_ = NULL;
    out_ = NULL;
  }

  EVP_PKEY* pkey_;
  unsigned char* out_;
};

static void Init(Handle<Object> target) {
  HandleScope scope;

  // Init OpenSSL
  OpenSSL_add_all_algorithms();
  RAND_poll();

  Local<FunctionTemplate> t = FunctionTemplate::New(Engine::New);

  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("Engine"));

  NODE_SET_PROTOTYPE_METHOD(t, "modExp", Engine::ModExp);

  target->Set(String::NewSymbol("Engine"), t->GetFunction());
}

}  // namespace splittls

NODE_MODULE(splittls_binding, splittls::Init);
