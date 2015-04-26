/*
 * Copyright (c) 2014 - 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <openssl/rc4.h>
#ifndef OPENSSL_NO_DES
#include <openssl/des.h>
#endif
#ifndef OPENSSL_NO_IDEA
#include <openssl/idea.h>
#endif
#ifndef OPENSSL_NO_BF
#include <openssl/blowfish.h>
#endif

#include "apps.h"
#include "buildinf.h"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_B,
    OPT_F,
    OPT_O,
    OPT_P,
    OPT_V,
    OPT_A
} OPTION_CHOICE;

OPTIONS version_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },
    { "a", OPT_A, '-', "Show all data" },
    { "b", OPT_B, '-', "Show build date" },
    { "f", OPT_F, '-', "Show compiler flags used" },
    { "o", OPT_O, '-', "Show some internal datatype options" },
    { "p", OPT_P, '-', "Show target build platform" },
    { "v", OPT_V, '-', "Show library version" },
    { NULL }
};

int version_main(int argc, char **argv)
{
    int ret = 1, dirty = 0;
    int cflags = 0, version = 0, date = 0, options = 0, platform = 0, dir = 0;
    char *prog;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, version_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(version_options);
                ret = 0;
                goto end;
            case OPT_B:
                dirty = date = 1;
                break;
            case OPT_F:
                dirty = cflags = 1;
                break;
            case OPT_O:
                dirty = options = 1;
                break;
            case OPT_P:
                dirty = platform = 1;
                break;
            case OPT_V:
                dirty = version = 1;
                break;
            case OPT_A:
                cflags = version = date = platform = dir = 1;
                break;
        }
    }
    if (!dirty)
        version = 1;

    if (version)
        printf("%s\n", OPENSSL_VERSION_TEXT);
    if (date)
        printf("Built on: %s at %s\n", BUILDDATE, BUILDTIME);
    if (platform)
        printf("Platform: %s\n", PLATFORM);
    if (options) {
        printf("Options:  ");
        printf("%s ", BN_options());
        printf("%s ", RC4_options());
#ifndef OPENSSL_NO_DES
        printf("%s ", DES_options());
#endif
#ifndef OPENSSL_NO_IDEA
        printf("%s ", idea_options());
#endif
#ifndef OPENSSL_NO_BF
        printf("%s ", BF_options());
#endif
        printf("\n");
    }
    if (cflags)
        printf("Compiler: %s\n", CFLAGS);
    ret = 0;
end:
    return ret;
}
