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

#ifndef HEADER_CHACHA_H
#define HEADER_CHACHA_H

#include <openssl/opensslconf.h>

#if defined(OPENSSL_NO_CHACHA)
#error ChaCha is disabled.
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int input[16];
    uint8_t ks[64];
    uint8_t unused;
} ChaCha_ctx;

void ChaCha_set_key(ChaCha_ctx *ctx, const uint8_t *key,
                    unsigned int keybits);
void ChaCha_set_iv(ChaCha_ctx *ctx, const uint8_t *iv,
                   const uint8_t *counter);
void ChaCha(ChaCha_ctx *ctx, uint8_t *out, const uint8_t *in,
            size_t inlen);

void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t inlen,
                      const uint8_t key[32], const uint8_t nonce[8], size_t counter);

#ifdef __cplusplus
}
#endif

#endif
