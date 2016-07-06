/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/bn.h>

/* Custom primitive type for BIGNUM handling. This reads in an ASN1_INTEGER as a
 * BIGNUM directly. Currently it ignores the sign which isn't a problem since all
 * BIGNUMs used are non negative and anything that looks negative is normally due
 * to an encoding error.
 */

#define BN_SENSITIVE 1

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it);

static int bn_i2c(ASN1_VALUE **pval, uint8_t *cont, int *putype, const ASN1_ITEM *it);
static int bn_c2i(ASN1_VALUE **pval, const uint8_t *cont, int len, int utype, char *free_cont, const ASN1_ITEM *it);

static ASN1_PRIMITIVE_FUNCS bignum_pf = {
    .prim_new = bn_new,
    .prim_free = bn_free,
    .prim_c2i = bn_c2i,
    .prim_i2c = bn_i2c,
};

ASN1_ITEM_start(BIGNUM)
    ASN1_ITYPE_PRIMITIVE,
    V_ASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUM" ASN1_ITEM_end(BIGNUM)

                                                ASN1_ITEM_start(CBIGNUM)
                                                    ASN1_ITYPE_PRIMITIVE,
    V_ASN1_INTEGER, NULL, 0, &bignum_pf, BN_SENSITIVE, "BIGNUM" ASN1_ITEM_end(CBIGNUM)

                                                           static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    *pval = (ASN1_VALUE *)BN_new();
    if (*pval)
        return 1;
    else
        return 0;
}

static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    if (!*pval)
        return;
    if (it->size & BN_SENSITIVE)
        BN_clear_free((BIGNUM *)*pval);
    else
        BN_free((BIGNUM *)*pval);
    *pval = NULL;
}

static int bn_i2c(ASN1_VALUE **pval, uint8_t *cont, int *putype, const ASN1_ITEM *it)
{
    BIGNUM *bn;
    int pad;
    if (!*pval)
        return -1;
    bn = (BIGNUM *)*pval;
    /* If MSB set in an octet we need a padding byte */
    if (BN_num_bits(bn) & 0x7)
        pad = 0;
    else
        pad = 1;
    if (cont) {
        if (pad)
            *cont++ = 0;
        BN_bn2bin(bn, cont);
    }
    return pad + BN_num_bytes(bn);
}

static int bn_c2i(ASN1_VALUE **pval, const uint8_t *cont, int len,
                  int utype, char *free_cont, const ASN1_ITEM *it)
{
    BIGNUM *bn;

    if (*pval == NULL && !bn_new(pval, it))
        return 0;
    bn = (BIGNUM *)*pval;
    if (!BN_bin2bn(cont, len, bn)) {
        bn_free(pval, it);
        return 0;
    }
    return 1;
}
