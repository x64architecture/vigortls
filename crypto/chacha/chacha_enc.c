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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_CHACHA

#include <stdint.h>

#include <openssl/chacha.h>

#include "chacha.c"

void ChaCha_set_key(ChaCha_ctx *ctx, const uint8_t *key,
                    uint32_t keybits)
{
    chacha_keysetup((chacha_ctx *)ctx, key, keybits);
    ctx->unused = 0;
}

void ChaCha_set_iv(ChaCha_ctx *ctx, const uint8_t *iv,
                   const uint8_t *counter)
{
    chacha_ivsetup((chacha_ctx *)ctx, iv, counter);
    ctx->unused = 0;
}

void ChaCha(ChaCha_ctx *ctx, uint8_t *out, const uint8_t *in,
            size_t inlen)
{
    uint8_t *k;
    int i, l;

    /* Consume remaining keystream, if there is any left. */
    if (ctx->unused > 0) {
        k = ctx->ks + 64 - ctx->unused;
        l = (inlen > ctx->unused) ? ctx->unused : inlen;
        for (i = 0; i < l; i++)
            *(out++) = *(in++) ^ *(k++);
        ctx->unused -= l;
        inlen -= l;
    }

    chacha_encrypt_bytes((chacha_ctx *)ctx, in, out, (uint32_t)inlen);
}

void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t key[32], const uint8_t nonce[8],
                      size_t counter)
{
    struct chacha_ctx ctx;

    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, nonce, NULL);

    if (counter != 0) {
        ctx.input[12] = (uint32_t)counter;
        ctx.input[13] = (uint32_t)(((uint64_t)counter) >> 32);
    }

    chacha_encrypt_bytes(&ctx, in, out, (uint32_t)inlen);
}

#endif
