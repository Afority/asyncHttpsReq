#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <iostream>

struct Crypto{
    SSL_CTX* ctx{};

    Crypto(){
        initCtx();
        initSSL();
    }

    ~Crypto(){
        // SSL_free(ssl);
    }

    void initSSL(){
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
    }

    void initCtx(){
        ctx = SSL_CTX_new(TLS_method());
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

        if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", nullptr)) {
          std::cerr << "Failed to load certificates" << std::endl;
          return;
        }
    }


};
