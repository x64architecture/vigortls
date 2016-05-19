/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <ctype.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "internal/x509_int.h"

int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b)
{
    int i;
    X509_CINF *ai, *bi;

    ai = a->cert_info;
    bi = b->cert_info;
    i = ASN1_INTEGER_cmp(ai->serialNumber, bi->serialNumber);
    if (i)
        return (i);
    return (X509_NAME_cmp(ai->issuer, bi->issuer));
}

unsigned long X509_issuer_and_serial_hash(X509 *a)
{
    unsigned long ret = 0;
    EVP_MD_CTX ctx;
    uint8_t md[16];
    char *f;

    EVP_MD_CTX_init(&ctx);
    f = X509_NAME_oneline(a->cert_info->issuer, NULL, 0);
    if (!EVP_DigestInit_ex(&ctx, EVP_md5(), NULL))
        goto err;
    if (!EVP_DigestUpdate(&ctx, (uint8_t *)f, strlen(f)))
        goto err;
    free(f);
    if (!EVP_DigestUpdate(&ctx, (uint8_t *)a->cert_info->serialNumber->data,
                          (unsigned long)a->cert_info->serialNumber->length))
        goto err;
    if (!EVP_DigestFinal_ex(&ctx, &(md[0]), NULL))
        goto err;
    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) | ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)) & 0xffffffffL;
err:
    EVP_MD_CTX_cleanup(&ctx);
    return (ret);
}

int X509_issuer_name_cmp(const X509 *a, const X509 *b)
{
    return (X509_NAME_cmp(a->cert_info->issuer, b->cert_info->issuer));
}

int X509_subject_name_cmp(const X509 *a, const X509 *b)
{
    return (X509_NAME_cmp(a->cert_info->subject, b->cert_info->subject));
}

int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b)
{
    return (X509_NAME_cmp(a->crl->issuer, b->crl->issuer));
}

int X509_CRL_match(const X509_CRL *a, const X509_CRL *b)
{
    return memcmp(a->sha1_hash, b->sha1_hash, 20);
}

X509_NAME *X509_get_issuer_name(X509 *a)
{
    return (a->cert_info->issuer);
}

unsigned long X509_issuer_name_hash(X509 *x)
{
    return (X509_NAME_hash(x->cert_info->issuer));
}

unsigned long X509_issuer_name_hash_old(X509 *x)
{
    return (X509_NAME_hash_old(x->cert_info->issuer));
}

X509_NAME *X509_get_subject_name(X509 *a)
{
    return (a->cert_info->subject);
}

ASN1_INTEGER *X509_get_serialNumber(X509 *a)
{
    return (a->cert_info->serialNumber);
}

unsigned long X509_subject_name_hash(X509 *x)
{
    return (X509_NAME_hash(x->cert_info->subject));
}

unsigned long X509_subject_name_hash_old(X509 *x)
{
    return (X509_NAME_hash_old(x->cert_info->subject));
}

/* Compare two certificates: they must be identical for
 * this to work. NB: Although "cmp" operations are generally
 * prototyped to take "const" arguments (eg. for use in
 * STACKs), the way X509 handling is - these operations may
 * involve ensuring the hashes are up-to-date and ensuring
 * certain cert information is cached. So this is the point
 * where the "depth-first" constification tree has to halt
 * with an evil cast.
 */
int X509_cmp(const X509 *a, const X509 *b)
{
    int rv;

    /* ensure hash is valid */
    X509_check_purpose((X509 *)a, -1, 0);
    X509_check_purpose((X509 *)b, -1, 0);

    rv = memcmp(a->sha1_hash, b->sha1_hash, SHA_DIGEST_LENGTH);
    if (rv)
        return rv;
    /* Check for match against stored encoding too */
    if (!a->cert_info->enc.modified && !b->cert_info->enc.modified) {
        rv = (int)(a->cert_info->enc.len - b->cert_info->enc.len);
        if (rv)
            return rv;
        return memcmp(a->cert_info->enc.enc, b->cert_info->enc.enc,
                      a->cert_info->enc.len);
    }
    return rv;
}

int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)
{
    int ret;

    /* Ensure canonical encoding is present and up to date */

    if (!a->canon_enc || a->modified) {
        ret = i2d_X509_NAME((X509_NAME *)a, NULL);
        if (ret < 0)
            return -2;
    }

    if (!b->canon_enc || b->modified) {
        ret = i2d_X509_NAME((X509_NAME *)b, NULL);
        if (ret < 0)
            return -2;
    }

    ret = a->canon_enclen - b->canon_enclen;

    if (ret)
        return ret;

    return memcmp(a->canon_enc, b->canon_enc, a->canon_enclen);
}

unsigned long X509_NAME_hash(X509_NAME *x)
{
    unsigned long ret = 0;
    uint8_t md[SHA_DIGEST_LENGTH];

    /* Make sure X509_NAME structure contains valid cached encoding */
    i2d_X509_NAME(x, NULL);
    if (!EVP_Digest(x->canon_enc, x->canon_enclen, md, NULL, EVP_sha1(),
                    NULL))
        return 0;

    ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) | ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)) & 0xffffffffL;
    return (ret);
}

/* I now DER encode the name and hash it.  Since I cache the DER encoding,
 * this is reasonably efficient. */

unsigned long X509_NAME_hash_old(X509_NAME *x)
{
    EVP_MD_CTX md_ctx;
    unsigned long ret = 0;
    uint8_t md[16];

    /* Make sure X509_NAME structure contains valid cached encoding */
    i2d_X509_NAME(x, NULL);
    EVP_MD_CTX_init(&md_ctx);
    if (EVP_DigestInit_ex(&md_ctx, EVP_md5(), NULL)
        && EVP_DigestUpdate(&md_ctx, x->bytes->data, x->bytes->length)
        && EVP_DigestFinal_ex(&md_ctx, md, NULL))
        ret = (((unsigned long)md[0]) | ((unsigned long)md[1] << 8L) | ((unsigned long)md[2] << 16L) | ((unsigned long)md[3] << 24L)) & 0xffffffffL;
    EVP_MD_CTX_cleanup(&md_ctx);

    return (ret);
}

/* Search a stack of X509 for a match */
X509 *X509_find_by_issuer_and_serial(STACK_OF(X509) * sk, X509_NAME * name,
                                     ASN1_INTEGER * serial)
{
    int i;
    X509_CINF cinf;
    X509 x, *x509 = NULL;

    if (!sk)
        return NULL;

    x.cert_info = &cinf;
    cinf.serialNumber = serial;
    cinf.issuer = name;

    for (i = 0; i < sk_X509_num(sk); i++) {
        x509 = sk_X509_value(sk, i);
        if (X509_issuer_and_serial_cmp(x509, &x) == 0)
            return (x509);
    }
    return (NULL);
}

X509 *X509_find_by_subject(STACK_OF(X509) * sk, X509_NAME * name)
{
    X509 *x509;
    int i;

    for (i = 0; i < sk_X509_num(sk); i++) {
        x509 = sk_X509_value(sk, i);
        if (X509_NAME_cmp(X509_get_subject_name(x509), name) == 0)
            return (x509);
    }
    return (NULL);
}

EVP_PKEY *X509_get_pubkey(X509 *x)
{
    if ((x == NULL) || (x->cert_info == NULL))
        return (NULL);
    return (X509_PUBKEY_get(x->cert_info->key));
}

ASN1_BIT_STRING *X509_get0_pubkey_bitstr(const X509 *x)
{
    if (!x)
        return NULL;
    return x->cert_info->key->public_key;
}

int X509_check_private_key(X509 *x, EVP_PKEY *k)
{
    EVP_PKEY *xk;
    int ret;

    xk = X509_get_pubkey(x);

    if (xk)
        ret = EVP_PKEY_cmp(xk, k);
    else
        ret = -2;

    switch (ret) {
        case 1:
            break;
        case 0:
            X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_KEY_VALUES_MISMATCH);
            break;
        case -1:
            X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_KEY_TYPE_MISMATCH);
            break;
        case -2:
            X509err(X509_F_X509_CHECK_PRIVATE_KEY, X509_R_UNKNOWN_KEY_TYPE);
    }
    if (xk)
        EVP_PKEY_free(xk);
    if (ret > 0)
        return 1;
    return 0;
}
