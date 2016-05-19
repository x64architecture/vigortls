/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_TLS1,
    OPT_V,
    OPT_UPPER_V
} OPTION_CHOICE;

OPTIONS ciphers_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },
    { "v", OPT_V, '-', "Verbose listing of the SSL/TLS ciphers" },
    { "V", OPT_UPPER_V, '-', "Even more verbose" },
    { "tls1", OPT_TLS1, '-', "TLS1 mode" },
    { NULL }
};

int ciphers_main(int argc, char **argv)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *sk = NULL;
    const SSL_METHOD *meth = SSLv23_server_method();
    int ret = 1, i, verbose = 0, Verbose = 0;
    const char *p;
    char *ciphers = NULL, *prog;
    char buf[512];
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, ciphers_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
            opthelp:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(ciphers_options);
                ret = 0;
                goto end;
            case OPT_V:
                verbose = 1;
                break;
            case OPT_UPPER_V:
                verbose = Verbose = 1;
                break;
            case OPT_TLS1:
                meth = TLSv1_client_method();
                break;
        }
    }
    argv = opt_rest();
    argc = opt_num_rest();

    if (argc == 1)
        ciphers = *argv;
    else if (argc != 0)
        goto opthelp;

    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
        goto err;
    if (ciphers != NULL) {
        if (!SSL_CTX_set_cipher_list(ctx, ciphers)) {
            BIO_printf(bio_err, "Error in cipher list\n");
            goto err;
        }
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto err;

    if (!verbose) {
        for (i = 0;; i++) {
            p = SSL_get_cipher_list(ssl, i);
            if (p == NULL)
                break;
            if (i != 0)
                BIO_printf(bio_out, ":");
            BIO_printf(bio_out, "%s", p);
        }
        BIO_printf(bio_out, "\n");
    } else { /* verbose */
        sk = SSL_get_ciphers(ssl);

        for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
            SSL_CIPHER *c;

            c = sk_SSL_CIPHER_value(sk, i);

            if (Verbose) {
                unsigned long id = SSL_CIPHER_get_id(c);
                int id0 = (int)(id >> 24);
                int id1 = (int)((id >> 16) & 0xffL);
                int id2 = (int)((id >> 8) & 0xffL);
                int id3 = (int)(id & 0xffL);

                if ((id & 0xff000000L) == 0x03000000L)
                    BIO_printf(bio_out, "          0x%02X,0x%02X - ", id2,
                               id3); /* SSL3 cipher */
                else
                    BIO_printf(bio_out, "0x%02X,0x%02X,0x%02X,0x%02X - ", id0, id1,
                               id2, id3); /* whatever */
            }

            BIO_puts(bio_out, SSL_CIPHER_description(c, buf, sizeof buf));
        }
    }

    ret = 0;
    goto end;
err:
    SSL_load_error_strings();
    ERR_print_errors(bio_err);
end:
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return ret;
}
