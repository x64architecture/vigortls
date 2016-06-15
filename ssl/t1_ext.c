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

/*
 * Initialise custom extensions flags to indicate neither sent nor
 * received.
 */
void custom_ext_init(custom_ext_methods *exts)
{
    size_t i;
    for (i = 0; i < exts->meths_count; i++)
        exts->meths[i].ext_flags = 0;
}

/* pass received custom extension data to the application for parsing */

int custom_ext_parse(SSL *s, int server, uint16_t ext_type,
                     const uint8_t *ext_data, uint16_t ext_size, int *al)
{
    custom_ext_methods *exts = server ? &s->cert->srv_ext : &s->cert->cli_ext;
    custom_ext_method *meth;
    meth = custom_ext_find(exts, ext_type);
    /* If not found or no parse function set, return success */
    /* If not found return success */
    if (meth == NULL)
        return 1;
    if (!server) {
        /*
         * If it's ServerHello we can't have any extensions not
         * sent in ClientHello.
         */
        if (!(meth->ext_flags & SSL_EXT_FLAG_SENT)) {
            *al = TLS1_AD_UNSUPPORTED_EXTENSION;
            return 0;
        }
    }
    /* If already present it's a duplicate */
    if (meth->ext_flags & SSL_EXT_FLAG_RECEIVED) {
        *al = TLS1_AD_DECODE_ERROR;
        return 0;
    }
    meth->ext_flags |= SSL_EXT_FLAG_RECEIVED;
    if (!meth->parse_cb)
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

        if (server) {
            /* For ServerHello only send extensions present in ClientHello. */
            if (!(meth->ext_flags & SSL_EXT_FLAG_RECEIVED))
                continue;
            /* If callback absent for server skip it */
            if (!meth->add_cb)
                continue;
        }
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
        /* We can't send duplicates: code logic should prevent this */
        OPENSSL_assert(!(meth->ext_flags & SSL_EXT_FLAG_SENT));
        /*
         * Indicate extension has been sent: this is both a sanity check to
         * ensure we don't send duplicate extensions and indicates to servers
         * that an extension can be sent in ServerHello.
         */
        meth->ext_flags |= SSL_EXT_FLAG_SENT;
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

    /* See if it is a supported internally */
    switch (ext_type) {
        case TLSEXT_TYPE_application_layer_protocol_negotiation:
        case TLSEXT_TYPE_ec_point_formats:
        case TLSEXT_TYPE_elliptic_curves:
        case TLSEXT_TYPE_heartbeat:
        case TLSEXT_TYPE_next_proto_neg:
        case TLSEXT_TYPE_padding:
        case TLSEXT_TYPE_renegotiate:
        case TLSEXT_TYPE_server_name:
        case TLSEXT_TYPE_session_ticket:
        case TLSEXT_TYPE_signature_algorithms:
        case TLSEXT_TYPE_srp:
        case TLSEXT_TYPE_status_request:
        case TLSEXT_TYPE_use_srtp:
#ifdef TLSEXT_TYPE_opaque_prf_input
        case TLSEXT_TYPE_opaque_prf_input:
#endif
#ifdef TLSEXT_TYPE_encrypt_then_mac
        case TLSEXT_TYPE_encrypt_then_mac:
#endif
            return 0;
    }
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
    memset(meth, 0, sizeof(custom_ext_method));
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