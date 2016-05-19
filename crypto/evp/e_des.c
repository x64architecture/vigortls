/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/objects.h>

#include "evp_locl.h"

typedef struct {
    union {
        double align;
        DES_key_schedule ks;
    } ks;
} EVP_DES_KEY;

static int des_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc)
{
    DES_cblock *deskey = (DES_cblock *)key;
    EVP_DES_KEY *dat = (EVP_DES_KEY *)ctx->cipher_data;

    DES_set_key(deskey, &dat->ks.ks);
    return 1;
}

static int des_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t in_len)
{
    EVP_DES_KEY *dat = (EVP_DES_KEY *)ctx->cipher_data;

    DES_ncbc_encrypt(in, out, in_len, &dat->ks.ks, (DES_cblock *)ctx->iv,
                     ctx->encrypt);

    return 1;
}

static const EVP_CIPHER des_cbc = {
    .nid        = NID_des_cbc,
    .block_size = 8,
    .key_len    = 8,
    .iv_len     = 8,
    .ctx_size   = sizeof(EVP_DES_KEY),
    .flags      = EVP_CIPH_CBC_MODE,
    .init       = des_init_key,
    .do_cipher  = des_cbc_cipher,
};

const EVP_CIPHER *EVP_des_cbc(void)
{
    return &des_cbc;
}

typedef struct {
    union {
        double align;
        DES_key_schedule ks[3];
    } ks;
} DES_EDE_KEY;

static int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                             const uint8_t *iv, int enc)
{
    DES_cblock *deskey = (DES_cblock *)key;
    DES_EDE_KEY *dat = (DES_EDE_KEY *)ctx->cipher_data;

    DES_set_key(&deskey[0], &dat->ks.ks[0]);
    DES_set_key(&deskey[1], &dat->ks.ks[1]);
    DES_set_key(&deskey[2], &dat->ks.ks[2]);

    return 1;
}

static int des_ede3_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                               const uint8_t *in, size_t in_len)
{
    DES_EDE_KEY *dat = (DES_EDE_KEY *)ctx->cipher_data;

    DES_ede3_cbc_encrypt(in, out, in_len, &dat->ks.ks[0], &dat->ks.ks[1],
                         &dat->ks.ks[2], (DES_cblock *)ctx->iv, ctx->encrypt);

    return 1;
}

static const EVP_CIPHER des3_cbc = {
    .nid        = NID_des_cbc,
    .block_size = 8,
    .key_len    = 24,
    .iv_len     = 8,
    .ctx_size   = sizeof(DES_EDE_KEY),
    .flags      = EVP_CIPH_CBC_MODE,
    .init       = des_ede3_init_key,
    .do_cipher  = des_ede3_cbc_cipher,
};

const EVP_CIPHER *EVP_des_ede3_cbc(void)
{
    return &des3_cbc;
}
