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

#include <openssl/poly1305.h>

#if defined(VIGORTLS_64_BIT)
#include "poly1305_64.h"
#elif defined(VIGORTLS_32_BIT)
#include "poly1305_32.h"
#endif

static inline void poly1305_update(poly1305_context *ctx, const uint8_t *m,
                                   size_t bytes)
{
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
    size_t i, want;

    /* handle leftover */
    if (st->leftover) {
        want = (POLY1305_BLOCK_SIZE - st->leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < POLY1305_BLOCK_SIZE)
            return;
        poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= POLY1305_BLOCK_SIZE) {
        want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++)
            st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}

void CRYPTO_poly1305_init(poly1305_context *ctx, const uint8_t key[32])
{
    poly1305_init(ctx, key);
}

void CRYPTO_poly1305_update(poly1305_context *ctx, const uint8_t *in,
                            size_t inlen)
{
    poly1305_update(ctx, in, inlen);
}

POLY1305_NOINLINE void CRYPTO_poly1305_finish(poly1305_context *ctx, uint8_t mac[16])
{
    poly1305_finish(ctx, mac);
}
