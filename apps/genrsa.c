/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "apps.h"

#define DEFBITS 2048

static int genrsa_cb(int p, int n, BN_GENCB *cb);

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_3,
    OPT_F4,
    OPT_ENGINE,
    OPT_OUT,
    OPT_PASSOUT,
    OPT_CIPHER
} OPTION_CHOICE;

OPTIONS genrsa_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },
    { "3", OPT_3, '-', "Use 3 for the E value" },
    { "F4", OPT_F4, '-', "Use F4 (0x10001) for the E value" },
    { "f4", OPT_F4, '-', "Use F4 (0x10001) for the E value" },
    { "out", OPT_OUT, 's', "Output the key to specified file" },
    { "passout", OPT_PASSOUT, 's', "Output file pass phrase source" },
    { "", OPT_CIPHER, '-', "Encrypt the output with any supported cipher" },
#ifndef OPENSSL_NO_ENGINE
    { "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
    { NULL }
};

int genrsa_main(int argc, char **argv)
{
    BN_GENCB cb;
    ENGINE *e = NULL;
    BIGNUM *bn = BN_new();
    BIO *out = NULL;
    RSA *rsa = NULL;
    const EVP_CIPHER *enc = NULL;
    int ret = 1, num = DEFBITS;
    unsigned long f4 = RSA_F4;
    char *outfile = NULL, *passoutarg = NULL, *passout = NULL;
    char *engine = NULL, *prog;
    char *hexe, *dece;
    OPTION_CHOICE o;

    if (bn == NULL)
        goto end;

    BN_GENCB_set(&cb, genrsa_cb, bio_err);

    prog = opt_init(argc, argv, genrsa_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                ret = 0;
                opt_help(genrsa_options);
                goto end;
            case OPT_3:
                f4 = 3;
                break;
            case OPT_F4:
                f4 = RSA_F4;
                break;
            case OPT_OUT:
                outfile = opt_arg();
            case OPT_ENGINE:
                engine = opt_arg();
                break;
            case OPT_PASSOUT:
                passoutarg = opt_arg();
                break;
            case OPT_CIPHER:
                if (!opt_cipher(opt_unknown(), &enc))
                    goto end;
                break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argv[0] && (!opt_int(argv[0], &num) || num <= 0))
        goto end;

    if (!app_passwd(NULL, passoutarg, NULL, &passout)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(engine, 0);
#endif

    out = bio_open_default(outfile, "w");
    if (out == NULL)
        goto end;

    BIO_printf(bio_err, "Generating RSA private key, %d bit long modulus\n", num);
#ifdef OPENSSL_NO_ENGINE
    rsa = RSA_new();
#else
    rsa = RSA_new_method(e);
#endif
    if (!rsa)
        goto end;

    if (!BN_set_word(bn, f4) || !RSA_generate_key_ex(rsa, num, bn, &cb))
        goto end;

    hexe = BN_bn2hex(rsa->e);
    dece = BN_bn2dec(rsa->e);
    if (hexe && dece) {
        BIO_printf(bio_err, "e is %s (0x%s)\n", dece, hexe);
    }
    free(hexe);
    free(dece);
    {
        PW_CB_DATA cb_data;
        cb_data.password = passout;
        cb_data.prompt_info = outfile;
        if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0,
                                         (pem_password_cb *)password_callback, &cb_data))
            goto end;
    }

    ret = 0;
end:
    BN_free(bn);
    RSA_free(rsa);
    BIO_free_all(out);
    free(passout);
    if (ret != 0)
        ERR_print_errors(bio_err);
    return ret;
}

static int genrsa_cb(int p, int n, BN_GENCB *cb)
{
    char c;

    select_symbol(p, &c);
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);
    return 1;
}
