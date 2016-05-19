/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/aes.h>
#include <openssl/bio.h>

static const uint8_t default_iv[] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
};

int AES_wrap_key(AES_KEY *key, const uint8_t *iv, uint8_t *out, const uint8_t *in,
                 unsigned int inlen)
{
    uint8_t *A, B[16], *R;
    unsigned int i, j, t;
    if ((inlen & 0x7) || (inlen < 8))
        return -1;
    A = B;
    t = 1;
    memcpy(out + 8, in, inlen);
    if (!iv)
        iv = default_iv;

    memcpy(A, iv, 8);

    for (j = 0; j < 6; j++) {
        R = out + 8;
        for (i = 0; i < inlen; i += 8, t++, R += 8) {
            memcpy(B + 8, R, 8);
            AES_encrypt(B, B, key);
            A[7] ^= (uint8_t)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (uint8_t)((t >> 8) & 0xff);
                A[5] ^= (uint8_t)((t >> 16) & 0xff);
                A[4] ^= (uint8_t)((t >> 24) & 0xff);
            }
            memcpy(R, B + 8, 8);
        }
    }
    memcpy(out, A, 8);
    return inlen + 8;
}

int AES_unwrap_key(AES_KEY *key, const uint8_t *iv, uint8_t *out, const uint8_t *in,
                   unsigned int inlen)
{
    uint8_t *A, B[16], *R;
    unsigned int i, j, t;
    inlen -= 8;
    if (inlen & 0x7)
        return -1;
    if (inlen < 8)
        return -1;
    A = B;
    t = 6 * (inlen >> 3);
    memcpy(A, in, 8);
    memcpy(out, in + 8, inlen);
    for (j = 0; j < 6; j++) {
        R = out + inlen - 8;
        for (i = 0; i < inlen; i += 8, t--, R -= 8) {
            A[7] ^= (uint8_t)(t & 0xff);
            if (t > 0xff) {
                A[6] ^= (uint8_t)((t >> 8) & 0xff);
                A[5] ^= (uint8_t)((t >> 16) & 0xff);
                A[4] ^= (uint8_t)((t >> 24) & 0xff);
            }
            memcpy(B + 8, R, 8);
            AES_decrypt(B, B, key);
            memcpy(R, B + 8, 8);
        }
    }
    if (!iv)
        iv = default_iv;
    if (memcmp(A, iv, 8)) {
        vigortls_zeroize(out, inlen);
        return 0;
    }
    return inlen;
}
