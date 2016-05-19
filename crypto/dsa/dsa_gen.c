/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                         const EVP_MD *evpmd, const uint8_t *seed_in,
                         size_t seed_len, uint8_t *seed_out, int *counter_ret,
                         unsigned long *h_ret, BN_GENCB *cb);

int DSA_generate_parameters_ex(DSA *ret, int bits,
                               const uint8_t *seed_in, int seed_len,
                               int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
{
    if (ret->meth->dsa_paramgen)
        return ret->meth->dsa_paramgen(ret, bits, seed_in, seed_len,
                                       counter_ret, h_ret, cb);
    else {
        const EVP_MD *evpmd;
        size_t qbits = bits >= 2048 ? 256 : 160;

        if (bits >= 2048) {
            qbits = 256;
            evpmd = EVP_sha256();
        } else {
            qbits = 160;
            evpmd = EVP_sha1();
        }

        return dsa_builtin_paramgen(ret, bits, qbits, evpmd,
                                    seed_in, seed_len, NULL, counter_ret, h_ret, cb);
    }
}

int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
                         const EVP_MD *evpmd, const uint8_t *seed_in, size_t seed_len,
                         uint8_t *seed_out,
                         int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)
{
    int ok = 0;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    uint8_t md[SHA256_DIGEST_LENGTH];
    uint8_t buf[SHA256_DIGEST_LENGTH], buf2[SHA256_DIGEST_LENGTH];
    BIGNUM *r0, *W, *X, *c, *test;
    BIGNUM *g = NULL, *q = NULL, *p = NULL;
    BN_MONT_CTX *mont = NULL;
    int i, k, n = 0, m = 0, qsize = qbits >> 3;
    int counter = 0;
    int r = 0;
    BN_CTX *ctx = NULL;
    unsigned int h = 2;

    if (qsize != SHA_DIGEST_LENGTH && qsize != SHA224_DIGEST_LENGTH && qsize != SHA256_DIGEST_LENGTH)
        /* invalid q size */
        return 0;

    if (evpmd == NULL)
        /* use SHA1 as default */
        evpmd = EVP_sha1();

    if (bits < 512)
        bits = 512;

    bits = (bits + 63) / 64 * 64;

    if (seed_len < (size_t)qsize) {
        seed_in = NULL; /* seed buffer too small -- ignore */
        seed_len = 0;
    }
    /*
     * App. 2.2 of FIPS PUB 186 allows larger SEED,
     * but our internal buffers are restricted to 160 bits
     */
    if (seed_len > (size_t)qsize)
        seed_len = qsize;

    if (seed_in != NULL)
        memcpy(seed, seed_in, seed_len);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    BN_CTX_start(ctx);

    if ((mont = BN_MONT_CTX_new()) == NULL)
        goto err;

    r0 = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);
    W = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    test = BN_CTX_get(ctx);

    if (!BN_lshift(test, BN_value_one(), bits - 1))
        goto err;

    for (;;) {
        for (;;) /* find q */
        {
            int seed_is_random;

            /* step 1 */
            if (!BN_GENCB_call(cb, 0, m++))
                goto err;

            if (seed_len == 0) {
                if (RAND_bytes(seed, qsize) <= 0)
                    goto err;
                seed_is_random = 1;
            } else {
                seed_is_random = 0;
                seed_len = 0; /* use random seed if 'seed_in' turns out to be bad*/
            }
            memcpy(buf, seed, qsize);
            memcpy(buf2, seed, qsize);
            /* precompute "SEED + 1" for step 7: */
            for (i = qsize - 1; i >= 0; i--) {
                buf[i]++;
                if (buf[i] != 0)
                    break;
            }

            /* step 2 */
            if (!EVP_Digest(seed, qsize, md, NULL, evpmd, NULL))
                goto err;
            if (!EVP_Digest(buf, qsize, buf2, NULL, evpmd, NULL))
                goto err;
            for (i = 0; i < qsize; i++)
                md[i] ^= buf2[i];

            /* step 3 */
            md[0] |= 0x80;
            md[qsize - 1] |= 0x01;
            if (!BN_bin2bn(md, qsize, q))
                goto err;

            /* step 4 */
            r = BN_is_prime_fasttest_ex(q, DSS_prime_checks, ctx,
                                        seed_is_random, cb);
            if (r > 0)
                break;
            if (r != 0)
                goto err;

            /* do a callback call */
            /* step 5 */
        }

        if (!BN_GENCB_call(cb, 2, 0))
            goto err;
        if (!BN_GENCB_call(cb, 3, 0))
            goto err;

        /* step 6 */
        counter = 0;
        /* "offset = 2" */

        n = (bits - 1) / 160;

        for (;;) {
            if ((counter != 0) && !BN_GENCB_call(cb, 0, counter))
                goto err;

            /* step 7 */
            BN_zero(W);
            /* now 'buf' contains "SEED + offset - 1" */
            for (k = 0; k <= n; k++) {
                /* obtain "SEED + offset + k" by incrementing: */
                for (i = qsize - 1; i >= 0; i--) {
                    buf[i]++;
                    if (buf[i] != 0)
                        break;
                }

                if (!EVP_Digest(buf, qsize, md, NULL, evpmd,
                                NULL))
                    goto err;

                /* step 8 */
                if (!BN_bin2bn(md, qsize, r0))
                    goto err;
                if (!BN_lshift(r0, r0, (qsize << 3) * k))
                    goto err;
                if (!BN_add(W, W, r0))
                    goto err;
            }

            /* more of step 8 */
            if (!BN_mask_bits(W, bits - 1))
                goto err;
            if (!BN_copy(X, W))
                goto err;
            if (!BN_add(X, X, test))
                goto err;

            /* step 9 */
            if (!BN_lshift1(r0, q))
                goto err;
            if (!BN_mod(c, X, r0, ctx))
                goto err;
            if (!BN_sub(r0, c, BN_value_one()))
                goto err;
            if (!BN_sub(p, X, r0))
                goto err;

            /* step 10 */
            if (BN_cmp(p, test) >= 0) {
                /* step 11 */
                r = BN_is_prime_fasttest_ex(p, DSS_prime_checks,
                                            ctx, 1, cb);
                if (r > 0)
                    goto end; /* found it */
                if (r != 0)
                    goto err;
            }

            /* step 13 */
            counter++;
            /* "offset = offset + n + 1" */

            /* step 14 */
            if (counter >= 4096)
                break;
        }
    }
end:
    if (!BN_GENCB_call(cb, 2, 1))
        goto err;

    /* We now need to generate g */
    /* Set r0=(p-1)/q */
    if (!BN_sub(test, p, BN_value_one()))
        goto err;
    if (!BN_div(r0, NULL, test, q, ctx))
        goto err;

    if (!BN_set_word(test, h))
        goto err;
    if (!BN_MONT_CTX_set(mont, p, ctx))
        goto err;

    for (;;) {
        /* g=test^r0%p */
        if (!BN_mod_exp_mont(g, test, r0, p, ctx, mont))
            goto err;
        if (!BN_is_one(g))
            break;
        if (!BN_add(test, test, BN_value_one()))
            goto err;
        h++;
    }

    if (!BN_GENCB_call(cb, 3, 1))
        goto err;

    ok = 1;
err:
    if (ok) {
        BN_free(ret->p);
        BN_free(ret->q);
        BN_free(ret->g);
        ret->p = BN_dup(p);
        ret->q = BN_dup(q);
        ret->g = BN_dup(g);
        if (ret->p == NULL || ret->q == NULL || ret->g == NULL) {
            ok = 0;
            goto err;
        }
        if (counter_ret != NULL)
            *counter_ret = counter;
        if (h_ret != NULL)
            *h_ret = h;
        if (seed_out != NULL)
            memcpy(seed_out, seed, qsize);
    }
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    BN_MONT_CTX_free(mont);
    return ok;
}
