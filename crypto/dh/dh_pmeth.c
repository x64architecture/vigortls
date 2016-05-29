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
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "internal/evp_int.h"

/* DH pkey context structure */

typedef struct {
    /* Parameter gen parameters */
    int prime_len;
    int generator;
    int use_dsa;
    int subprime_len;
    const EVP_MD *md;
    int rfc5114_param;
    /* Keygen callback info */
    int gentmp[2];
    /* message digest */
} DH_PKEY_CTX;

static int pkey_dh_init(EVP_PKEY_CTX *ctx)
{
    DH_PKEY_CTX *dctx;
    dctx = malloc(sizeof(DH_PKEY_CTX));
    if (dctx == NULL)
        return 0;
    dctx->prime_len = 1024;
    dctx->subprime_len = -1;
    dctx->generator = 2;
    dctx->use_dsa = 0;
    dctx->md = NULL;
    dctx->rfc5114_param = 0;

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
    dctx->subprime_len = sctx->subprime_len;
    dctx->generator = sctx->generator;
    dctx->use_dsa = sctx->use_dsa;
    dctx->md = sctx->md;
    dctx->rfc5114_param = sctx->rfc5114_param;

    return 1;
}

static void pkey_dh_cleanup(EVP_PKEY_CTX *ctx)
{
    DH_PKEY_CTX *dctx = ctx->data;
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

        case EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN:
            if (dctx->use_dsa == 0)
                return -2;
            dctx->subprime_len = p1;
            return 1;

        case EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR:
            if (dctx->use_dsa)
                return -2;
            dctx->generator = p1;
            return 1;

        case EVP_PKEY_CTRL_DH_PARAMGEN_TYPE:
            if (p1 < 0 || p1 > 2)
                return -2;
            dctx->use_dsa = p1;
            return 1;

        case EVP_PKEY_CTRL_DH_RFC5114:
            if (p1 < 1 || p1 > 3)
                return -2;
            dctx->rfc5114_param = p1;
            return 1;

        case EVP_PKEY_CTRL_PEER_KEY:
            /* Default behaviour is OK */
            return 1;

        default:
            return -2;
    }
}

static int safe_atoi(const char *numstr, int min, int max, uint8_t *error)
{
    long lval;
    char *ep;

    errno = 0;
    lval = strtol(numstr, &ep, 10);
    if (numstr[0] == '\0' || *ep != '\0')
        goto invalid_number;
    if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
        (lval < min || lval > min))
        goto out_of_range;

    *error = 0;
    return (int)lval;

invalid_number:
out_of_range:
    *error = 1;
    return -2;
}

static int pkey_dh_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
    uint8_t error;

    if (strcmp(type, "dh_paramgen_prime_len") == 0) {
        int len;
        len = safe_atoi(value, INT_MIN, INT_MAX, &error);
        if (error)
            return -2;
        return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len);
    } else if (strcmp(type, "dh_rfc5114") == 0) {
        DH_PKEY_CTX *dctx = ctx->data;
        int len;
        len = safe_atoi(value, 0, 3, &error);
        if (error)
            return -2;
        dctx->rfc5114_param = len;
        return 1;
    } else if (strcmp(type, "dh_paramgen_generator") == 0) {
        int len;
        len = safe_atoi(value, INT_MIN, INT_MAX, &error);
        if (error)
            return -2;
        return EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, len);
    } else if (strcmp(type, "dh_paramgen_subprime_len") == 0) {
        int len;
        len = safe_atoi(value, INT_MIN, INT_MAX, &error);
        if (error)
            return -2;
        return EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len);
    } else if (strcmp(type, "dh_paramgen_type") == 0) {
        int type;
        type = safe_atoi(value, INT_MIN, INT_MAX, &error);
        if (error)
            return -2;
        return EVP_PKEY_CTX_set_dh_paramgen_type(ctx, type);
    }

    return -2;
}

extern int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                                const EVP_MD *evpmd, const uint8_t *seed_in,
                                size_t seed_len, uint8_t *seed_out,
                                int *counter_ret, unsigned long *h_ret,
                                BN_GENCB *cb);

extern int dsa_builtin_paramgen2(DSA *ret, size_t L, size_t N,
                                 const EVP_MD *evpmd, const uint8_t *seed_in,
                                 size_t seed_len, int idx, uint8_t *seed_out,
                                 int *counter_ret, unsigned long *h_ret,
                                 BN_GENCB *cb);

static DSA *dsa_dh_generate(DH_PKEY_CTX *dctx, BN_GENCB *pcb)
{
    DSA *ret;
    int rv = 0;
    int prime_len = dctx->prime_len;
    int subprime_len = dctx->subprime_len;
    const EVP_MD *md = dctx->md;
    if (dctx->use_dsa > 2)
        return NULL;
    ret = DSA_new();
    if (ret == NULL)
        return NULL;
    if (subprime_len == -1) {
        if (prime_len >= 2048)
            subprime_len = 256;
        else
            subprime_len = 160;
    }
    if (md == NULL) {
        if (prime_len >= 2048)
            md = EVP_sha256();
        else
            md = EVP_sha1();
    }
    if (dctx->use_dsa == 1)
        rv = dsa_builtin_paramgen(ret, prime_len, subprime_len, md, NULL, 0,
                                  NULL, NULL, NULL, pcb);
    else if (dctx->use_dsa == 2)
        rv = dsa_builtin_paramgen2(ret, prime_len, subprime_len, md, NULL, 0,
                                   -1, NULL, NULL, NULL, pcb);
    if (rv <= 0) {
        DSA_free(ret);
        return NULL;
    }
    return ret;
}

static int pkey_dh_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    DH *dh = NULL;
    DH_PKEY_CTX *dctx = ctx->data;
    BN_GENCB *pcb, cb;
    int ret;

    if (dctx->rfc5114_param) {
        switch (dctx->rfc5114_param) {
            case 1:
                dh = DH_get_1024_160();
                break;
            case 2:
                dh = DH_get_2048_224();
                break;
            case 3:
                dh = DH_get_2048_256();
                break;
            default:
                return -2;
        }
        EVP_PKEY_assign(pkey, EVP_PKEY_DHX, dh);
        return 1;
    }

    if (ctx->pkey_gencb) {
        pcb = &cb;
        evp_pkey_set_cb_translate(pcb, ctx);
    } else
        pcb = NULL;
    if (dctx->use_dsa) {
        DSA *dsa_dh;
        dsa_dh = dsa_dh_generate(dctx, pcb);
        if (dsa_dh == NULL)
            return 0;
        dh = DSA_dup_DH(dsa_dh);
        DSA_free(dsa_dh);
        if (dh == NULL)
            return 0;
        EVP_PKEY_assign(pkey, EVP_PKEY_DHX, dh);
        return 1;
    }
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
    DH *dh;
    if (ctx->pkey == NULL) {
        DHerr(DH_F_PKEY_DH_KEYGEN, DH_R_NO_PARAMETERS_SET);
        return 0;
    }
    dh = DH_new();
    if (dh == NULL)
        return 0;
    EVP_PKEY_assign(pkey, ctx->pmeth->pkey_id, dh);
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
    .pkey_id = EVP_PKEY_DH,
    .flags = EVP_PKEY_FLAG_AUTOARGLEN,
    .init = pkey_dh_init,
    .copy = pkey_dh_copy,
    .cleanup = pkey_dh_cleanup,
    .paramgen = pkey_dh_paramgen,

    .keygen = pkey_dh_keygen,
    .derive = pkey_dh_derive,

    .ctrl = pkey_dh_ctrl,
    .ctrl_str = pkey_dh_ctrl_str
};

const EVP_PKEY_METHOD dhx_pkey_meth = {
    .pkey_id = EVP_PKEY_DHX,
    .flags = EVP_PKEY_FLAG_AUTOARGLEN,
    .init = pkey_dh_init,
    .copy = pkey_dh_copy,
    .cleanup = pkey_dh_cleanup,
    .paramgen = pkey_dh_paramgen,

    .keygen = pkey_dh_keygen,
    .derive = pkey_dh_derive,

    .ctrl = pkey_dh_ctrl,
    .ctrl_str = pkey_dh_ctrl_str
};
