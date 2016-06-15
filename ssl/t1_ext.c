/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Custom extension utility functions */

#include <stdcompat.h>
#include "ssl_locl.h"

/* Find a custom extension from the list */

static custom_ext_method *custom_ext_find(custom_ext_methods *exts,
                                          uint16_t ext_type)
{
    size_t i;
    custom_ext_method *meth = exts->meths;
    for (i = 0; i < exts->meths_count; i++, meth++) {
        if (ext_type == meth->ext_type)
            return meth;
    }
    return NULL;
}

/* pass received custom extension data to the application for parsing */

int custom_ext_parse(SSL *s, int server, uint16_t ext_type,
                     const uint8_t *ext_data, uint16_t ext_size, int *al)
{
    custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
    custom_ext_method *meth;
    meth = custom_ext_find(exts, ext_type);
    /* If not found or no parse function set, return success */
    if (!meth || !meth->parse_cb)
        return 1;

    return meth->parse_cb(s, ext_type, ext_data, ext_size, al, meth->arg);
}

/*
 * request custom extension data from the application and add to the
 * return buffer
 */

int custom_ext_add(SSL *s, int server, uint8_t **pret, uint8_t *limit, int *al)
{
    custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
    custom_ext_method *meth;
    uint8_t *ret = *pret;
    size_t i;

    for (i = 0; i < exts->meths_count; i++) {
        const uint8_t *out = NULL;
        uint16_t outlen = 0;
        meth = exts->meths + i;

        /*
         * For servers no callback omits extension,
         * For clients it sends empty extension.
         */
        if (server && !meth->add_cb)
            continue;
        if (meth->add_cb) {
            int cb_retval = 0;
            cb_retval =
                meth->add_cb(s, meth->ext_type, &out, &outlen, al, meth->arg);
            if (cb_retval == 0)
                return 0; /* error */
            if (cb_retval == -1)
                continue; /* skip this extension */
        }
        if (4 > limit - ret || outlen > limit - ret - 4)
            return 0;
        s2n(meth->ext_type, ret);
        s2n(outlen, ret);
        if (outlen) {
            memcpy(ret, out, outlen);
            ret += outlen;
        }
    }
    *pret = ret;
    return 1;
}

/* Copy table of custom extensions */

int custom_exts_copy(custom_ext_methods *dst, const custom_ext_methods *src)
{
    if (src->meths_count) {
        dst->meths = reallocarray(NULL, src->meths_count,
                        sizeof(custom_ext_method));
        if (dst->meths == NULL)
            return 0;
        memcpy(dst->meths, src->meths,
            src->meths_count * sizeof(custom_ext_method));
        dst->meths_count = src->meths_count;
    }
    return 1;
}

void custom_exts_free(custom_ext_methods *exts)
{
    free(exts->meths);
}

/* Set callbacks for a custom extension */
static int custom_ext_set(custom_ext_methods *exts, uint16_t ext_type,
                          custom_ext_parse_cb parse_cb,
                          custom_ext_add_cb add_cb, void *arg)
{
    custom_ext_method *meth;
    /* Search for duplicate */
    if (custom_ext_find(exts, ext_type))
        return 0;
    exts->meths = reallocarray(exts->meths, (exts->meths_count + 1),
                      sizeof(custom_ext_method));
    if (exts->meths == NULL) {
        exts->meths_count = 0;
        return 0;
    }

    meth = exts->meths + exts->meths_count;
    meth->parse_cb = parse_cb;
    meth->add_cb = add_cb;
    meth->ext_type = ext_type;
    meth->arg = arg;
    exts->meths_count++;
    return 1;
}

/* Application level functions to add custom extension callbacks */

int SSL_CTX_set_custom_cli_ext(SSL_CTX *ctx, uint16_t ext_type,
                               custom_cli_ext_first_cb_fn fn1,
                               custom_cli_ext_second_cb_fn fn2, void *arg)
{
    return custom_ext_set(&ctx->cert->cli_ext, ext_type, fn2, fn1, arg);
}

int SSL_CTX_set_custom_srv_ext(SSL_CTX *ctx, uint16_t ext_type,
                               custom_srv_ext_first_cb_fn fn1,
                               custom_srv_ext_second_cb_fn fn2, void *arg)
{
    return custom_ext_set(&ctx->cert->srv_ext, ext_type, fn1, fn2, arg);
}