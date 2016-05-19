/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "ecs_locl.h"
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/bn.h>

static const ECDSA_METHOD *default_ECDSA_method = NULL;

static void *ecdsa_data_new(void);
static void *ecdsa_data_dup(void *);
static void ecdsa_data_free(void *);

void ECDSA_set_default_method(const ECDSA_METHOD *meth)
{
    default_ECDSA_method = meth;
}

const ECDSA_METHOD *ECDSA_get_default_method(void)
{
    if (!default_ECDSA_method) {
        default_ECDSA_method = ECDSA_OpenSSL();
    }
    return default_ECDSA_method;
}

int ECDSA_set_method(EC_KEY *eckey, const ECDSA_METHOD *meth)
{
    ECDSA_DATA *ecdsa;

    ecdsa = ecdsa_check(eckey);

    if (ecdsa == NULL)
        return 0;

#ifndef OPENSSL_NO_ENGINE
    if (ecdsa->engine) {
        ENGINE_finish(ecdsa->engine);
        ecdsa->engine = NULL;
    }
#endif
    ecdsa->meth = meth;

    return 1;
}

static ECDSA_DATA *ECDSA_DATA_new_method(ENGINE *engine)
{
    ECDSA_DATA *ret;

    ret = malloc(sizeof(ECDSA_DATA));
    if (ret == NULL) {
        ECDSAerr(ECDSA_F_ECDSA_DATA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    ret->init = NULL;

    ret->meth = ECDSA_get_default_method();
    ret->engine = engine;
#ifndef OPENSSL_NO_ENGINE
    if (!ret->engine)
        ret->engine = ENGINE_get_default_ECDSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_ECDSA(ret->engine);
        if (!ret->meth) {
            ECDSAerr(ECDSA_F_ECDSA_DATA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            free(ret);
            return NULL;
        }
    }
#endif

    ret->flags = ret->meth->flags;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ECDSA, ret, &ret->ex_data);
    return (ret);
}

static void *ecdsa_data_new(void)
{
    return (void *)ECDSA_DATA_new_method(NULL);
}

static void *ecdsa_data_dup(void *data)
{
    ECDSA_DATA *r = (ECDSA_DATA *)data;

    /* XXX: dummy operation */
    if (r == NULL)
        return NULL;

    return ecdsa_data_new();
}

static void ecdsa_data_free(void *data)
{
    ECDSA_DATA *r = (ECDSA_DATA *)data;

#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ECDSA, r, &r->ex_data);

    vigortls_zeroize((void *)r, sizeof(ECDSA_DATA));

    free(r);
}

ECDSA_DATA *ecdsa_check(EC_KEY *key)
{
    ECDSA_DATA *ecdsa_data;

    void *data = EC_KEY_get_key_method_data(key, ecdsa_data_dup,
                                            ecdsa_data_free, ecdsa_data_free);
    if (data == NULL) {
        ecdsa_data = (ECDSA_DATA *)ecdsa_data_new();
        if (ecdsa_data == NULL)
            return NULL;
        data = EC_KEY_insert_key_method_data(key, (void *)ecdsa_data,
                                             ecdsa_data_dup, ecdsa_data_free, ecdsa_data_free);
        if (data != NULL) {
            /* Another thread raced us to install the key_method
             * data and won. */
            ecdsa_data_free(ecdsa_data);
            ecdsa_data = (ECDSA_DATA *)data;
        }
    } else
        ecdsa_data = (ECDSA_DATA *)data;

    return ecdsa_data;
}

int ECDSA_size(const EC_KEY *r)
{
    int ret, i;
    ASN1_INTEGER bs;
    BIGNUM *order = NULL;
    uint8_t buf[4];
    const EC_GROUP *group;

    if (r == NULL)
        return 0;
    group = EC_KEY_get0_group(r);
    if (group == NULL)
        return 0;

    if ((order = BN_new()) == NULL)
        return 0;
    if (!EC_GROUP_get_order(group, order, NULL)) {
        BN_clear_free(order);
        return 0;
    }
    i = BN_num_bits(order);
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_ASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_ASN1_INTEGER(&bs, NULL);
    i += i; /* r and s */
    ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
    BN_clear_free(order);
    return (ret);
}

int ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                           CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ECDSA, argl, argp,
                                   new_func, dup_func, free_func);
}

int ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg)
{
    ECDSA_DATA *ecdsa;
    ecdsa = ecdsa_check(d);
    if (ecdsa == NULL)
        return 0;
    return (CRYPTO_set_ex_data(&ecdsa->ex_data, idx, arg));
}

void *ECDSA_get_ex_data(EC_KEY *d, int idx)
{
    ECDSA_DATA *ecdsa;
    ecdsa = ecdsa_check(d);
    if (ecdsa == NULL)
        return NULL;
    return (CRYPTO_get_ex_data(&ecdsa->ex_data, idx));
}
