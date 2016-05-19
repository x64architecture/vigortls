/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "apps.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_OUT,
    OPT_ENGINE,
    OPT_BASE64,
    OPT_HEX
} OPTION_CHOICE;

OPTIONS rand_options[] = {
    { OPT_HELP_STR, 1, '-', "Usage: %s [flags] num\n" },
    { OPT_HELP_STR, 1, '-', "Valid options are:\n" },
    { "help", OPT_HELP, '-', "Display this summary" },
    { "out", OPT_OUT, '>', "Output file" },
    { "base64", OPT_BASE64, '-', "Base64 encode output" },
    { "hex", OPT_HEX, '-', "Hex encode output" },
#ifndef OPENSSL_NO_ENGINE
    { "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
    { NULL }
};

int rand_main(int argc, char **argv)
{
    BIO *out = NULL;
    char *engine = NULL, *outfile = NULL, *prog;
    OPTION_CHOICE o;
    int base64 = 0, hex = 0, i, num = -1, r, ret = 1;

    prog = opt_init(argc, argv, rand_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
            opthelp:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(rand_options);
                ret = 0;
                goto end;
            case OPT_OUT:
                outfile = opt_arg();
                break;
            case OPT_ENGINE:
                engine = opt_arg();
                break;
            case OPT_BASE64:
                base64 = 1;
                break;
            case OPT_HEX:
                hex = 1;
                break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc != 1 || (hex && base64))
        goto opthelp;
    if (sscanf(argv[0], "%d", &num) != 1 || num < 0)
        goto opthelp;

#ifndef OPENSSL_NO_ENGINE
    setup_engine(engine, 0);
#endif

    out = bio_open_default(outfile, "w");
    if (out == NULL)
        goto end;

    if (base64) {
        BIO *b64 = BIO_new(BIO_f_base64());
        if (b64 == NULL)
            goto end;
        out = BIO_push(b64, out);
    }

    while (num > 0) {
        uint8_t buf[4096];
        int chunk;

        chunk = num;
        if (chunk > (int)sizeof(buf))
            chunk = sizeof buf;
        r = RAND_bytes(buf, chunk);
        if (r <= 0)
            goto end;
        if (!hex)
            BIO_write(out, buf, chunk);
        else {
            for (i = 0; i < chunk; i++)
                BIO_printf(out, "%02x", buf[i]);
        }
        num -= chunk;
    }
    if (hex)
        BIO_puts(out, "\n");
    (void)BIO_flush(out);

    ret = 0;

end:
    BIO_free_all(out);
    return (ret);
}
