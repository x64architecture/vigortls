/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#include <openssl/asn1t.h>

/* Override the default free and new methods */
static int dh_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                 void *exarg)
{
    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)DH_new();
        if (*pval)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        DH_free((DH *)*pval);
        *pval = NULL;
        return 2;
    }
    return 1;
}

ASN1_SEQUENCE_cb(DHparams, dh_cb) = {
    ASN1_SIMPLE(DH, p, BIGNUM),
    ASN1_SIMPLE(DH, g, BIGNUM),
    ASN1_OPT(DH, length, ZLONG),
} ASN1_SEQUENCE_END_cb(DH, DHparams)

DH *d2i_DHparams(DH **a, const uint8_t **in, long len)
{
    return (DH *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                               &DHparams_it);
}

int i2d_DHparams(const DH *a, uint8_t **out)
{
    return ASN1_item_i2d((ASN1_VALUE *)a, out, &DHparams_it);
}

DH *DHparams_dup(DH *dh)
{
    return ASN1_item_dup(ASN1_ITEM_rptr(DHparams), dh);
}
