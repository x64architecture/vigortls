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

extern void poly1305_init(poly1305_context *ctx, const uint8_t key[32]);
extern void poly1305_update(poly1305_context *ctx, const uint8_t *m,
                            size_t bytes);
extern void poly1305_finish(poly1305_context *ctx, uint8_t mac[16]);

extern void CRYPTO_poly1305_init(poly1305_context *ctx, const unsigned char key[32])
{
    poly1305_init(ctx, key);
}

void CRYPTO_poly1305_update(poly1305_context *ctx, const unsigned char *in,
                            size_t inlen)
{
    poly1305_update(ctx, in, inlen);
}

void CRYPTO_poly1305_finish(poly1305_context *ctx, unsigned char mac[16])
{
    poly1305_finish(ctx, mac);
}
