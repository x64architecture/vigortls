/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

ASN1_SEQUENCE(X509_SIG) = {
    ASN1_SIMPLE(X509_SIG, algor, X509_ALGOR),
    ASN1_SIMPLE(X509_SIG, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_SIG)

X509_SIG *d2i_X509_SIG(X509_SIG **a, const uint8_t **in, long len)
{
    return (X509_SIG *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, &X509_SIG_it);
}

int i2d_X509_SIG(X509_SIG *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, &X509_SIG_it);
}

X509_SIG *X509_SIG_new(void)
{
    return (X509_SIG *)ASN1_item_new(&X509_SIG_it);
}

void X509_SIG_free(X509_SIG *a)
{
    ASN1_item_free((ASN1_VALUE *)a, &X509_SIG_it);
}
