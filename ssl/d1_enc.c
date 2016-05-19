/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

/* dtls1_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|,
 *respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding/AEAD-authenticator is invalid or, if sending,
 *       an internal error occured. */
int dtls1_enc(SSL *s, int send)
{
    SSL3_RECORD *rec;
    EVP_CIPHER_CTX *ds;
    unsigned long l;
    int bs, i, j, k, mac_size = 0;
    const EVP_CIPHER *enc;

    if (send) {
        if (EVP_MD_CTX_md(s->write_hash)) {
            mac_size = EVP_MD_CTX_size(s->write_hash);
            if (mac_size < 0)
                return -1;
        }
        ds = s->enc_write_ctx;
        rec = &(s->s3->wrec);
        if (s->enc_write_ctx == NULL)
            enc = NULL;
        else {
            enc = EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
            if (rec->data != rec->input)
                /* we can't write into the input stream */
                fprintf(stderr, "%s:%d: rec->data != rec->input\n", __FILE__, __LINE__);
            else if (EVP_CIPHER_block_size(ds->cipher) > 1) {
                if (RAND_bytes(rec->input, EVP_CIPHER_block_size(ds->cipher)) <= 0)
                    return -1;
            }
        }
    } else {
        if (EVP_MD_CTX_md(s->read_hash)) {
            mac_size = EVP_MD_CTX_size(s->read_hash);
            OPENSSL_assert(mac_size >= 0);
        }
        ds = s->enc_read_ctx;
        rec = &(s->s3->rrec);
        if (s->enc_read_ctx == NULL)
            enc = NULL;
        else
            enc = EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
    }

    if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
        memmove(rec->data, rec->input, rec->length);
        rec->input = rec->data;
    } else {
        l = rec->length;
        bs = EVP_CIPHER_block_size(ds->cipher);

        if ((bs != 1) && send) {
            i = bs - ((int)l % bs);

            /* Add weird padding of upto 256 bytes */

            /* we need to add 'i' padding bytes of value j */
            j = i - 1;
            for (k = (int)l; k < (int)(l + i); k++)
                rec->input[k] = j;
            l += i;
            rec->length += i;
        }

        if (!send) {
            if (l == 0 || l % bs != 0)
                return 0;
        }

        if (EVP_Cipher(ds, rec->data, rec->input, l) < 1)
            return -1;

        if ((bs != 1) && !send)
            return tls1_cbc_remove_padding(s, rec, bs, mac_size);
    }
    return (1);
}
