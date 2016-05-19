/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "internal/evp_int.h"

/* DH pkey context structure */

typedef struct
    {
    /* Parameter gen parameters */
    int prime_len;
    int generator;
    int use_dsa;
    /* Keygen callback info */
    int gentmp[2];
    /* message digest */
} DH_PKEY_CTX;

static int pkey_dh_init(EVP_PKEY_CTX *ctx)
{
    DH_PKEY_CTX *dctx;
    dctx = malloc(sizeof(DH_PKEY_CTX));
    if (!dctx)
        return 0;
    dctx->prime_len = 1024;
    dctx->generator = 2;
    dctx->use_dsa = 0;

    ctx->data = dctx;
    ctx->keygen_info = dctx->gentmp;
    ctx->keygen_info_count = 2;

    return 1;
}

static int pkey_dh_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    DH_PKEY_CTX *dctx, *sctx;
    if (!pkey_dh_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    dctx->prime_len = sctx->prime_len;
    dctx->generator = sctx->generator;
    dctx->use_dsa = sctx->use_dsa;
    return 1;
}

static void pkey_dh_cleanup(EVP_PKEY_CTX *ctx)
{
    DH_PKEY_CTX *dctx = ctx->data;
    if (dctx)
        free(dctx);
}

static int pkey_dh_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    DH_PKEY_CTX *dctx = ctx->data;
    switch (type) {
        case EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN:
            if (p1 < 256)
                return -2;
            dctx->prime_len = p1;
            return 1;

        case EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR:
            dctx->generator = p1;
            return 1;

        case EVP_PKEY_CTRL_PEER_KEY:
            /* Default behaviour is OK */
            return 1;

        default:
            return -2;
    }
}

static int pkey_dh_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    long lval;
    char *ep;
    int len;
    if (strcmp(type, "dh_paramgen_prime_len") == 0) {
        errno = 0;
        lval = strtol(value, &ep, 10);
        if (value[0] == '\0' || *ep != '\0')
            goto invalid_number;
        if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
            (lval > INT_MAX || lval < INT_MIN))
            goto out_of_range;
        len = lval;
        return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len);
    }
    if (strcmp(type, "dh_paramgen_generator") == 0) {
        errno = 0;
        lval = strtol(value, &ep, 10);
        if (value[0] == '\0' || *ep != '\0')
            goto invalid_number;
        if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
            (lval > INT_MAX || lval < INT_MIN))
            goto out_of_range;
        len = lval;
        return EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, len);
    }
invalid_number:
out_of_range:
    return -2;
}

static int pkey_dh_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DH *dh = NULL;
    DH_PKEY_CTX *dctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;
    if (ctx->pkey_gencb) {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    } else
        pcb = NULL;
    dh = DH_new();
    if (!dh)
        return 0;
    ret = DH_generate_parameters_ex(dh,
                                    dctx->prime_len, dctx->generator, pcb);
    if (ret)
        EVP_PKEY_assign_DH(pkey, dh);
    else
        DH_free(dh);
    return ret;
}

static int pkey_dh_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DH *dh = NULL;
    if (ctx->pkey == NULL) {
        DHerr(DH_F_PKEY_DH_KEYGEN, DH_R_NO_PARAMETERS_SET);
        return 0;
    }
    dh = DH_new();
    if (!dh)
        return 0;
    EVP_PKEY_assign_DH(pkey, dh);
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
        return 0;
    return DH_generate_key(pkey->pkey.dh);
}

static int pkey_dh_derive(EVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen)
{
    int ret;
    if (!ctx->pkey || !ctx->peerkey) {
        DHerr(DH_F_PKEY_DH_DERIVE, DH_R_KEYS_NOT_SET);
        return 0;
    }
    ret = DH_compute_key(key, ctx->peerkey->pkey.dh->pub_key,
                         ctx->pkey->pkey.dh);
    if (ret < 0)
        return ret;
    *keylen = ret;
    return 1;
}

const EVP_PKEY_METHOD dh_pkey_meth = {
    EVP_PKEY_DH,
    EVP_PKEY_FLAG_AUTOARGLEN,
    pkey_dh_init,
    pkey_dh_copy,
    pkey_dh_cleanup,

    0,
    pkey_dh_paramgen,

    0,
    pkey_dh_keygen,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    0,
    pkey_dh_derive,

    pkey_dh_ctrl,
    pkey_dh_ctrl_str

};
