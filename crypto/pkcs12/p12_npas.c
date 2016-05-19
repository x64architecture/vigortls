/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* PKCS#12 password change routine */

static int newpass_p12(PKCS12 *p12, char *oldpass, char *newpass);
static int newpass_bags(STACK_OF(PKCS12_SAFEBAG) * bags, char *oldpass,
                        char *newpass);
static int newpass_bag(PKCS12_SAFEBAG *bag, char *oldpass, char *newpass);
static int alg_get(X509_ALGOR *alg, int *pnid, int *piter, int *psaltlen);

/*
 * Change the password on a PKCS#12 structure.
 */

int PKCS12_newpass(PKCS12 *p12, char *oldpass, char *newpass)
{
    /* Check for NULL PKCS12 structure */

    if (!p12) {
        PKCS12err(PKCS12_F_PKCS12_NEWPASS, PKCS12_R_INVALID_NULL_PKCS12_POINTER);
        return 0;
    }

    /* Check the mac */

    if (!PKCS12_verify_mac(p12, oldpass, -1)) {
        PKCS12err(PKCS12_F_PKCS12_NEWPASS, PKCS12_R_MAC_VERIFY_FAILURE);
        return 0;
    }

    if (!newpass_p12(p12, oldpass, newpass)) {
        PKCS12err(PKCS12_F_PKCS12_NEWPASS, PKCS12_R_PARSE_ERROR);
        return 0;
    }

    return 1;
}

/* Parse the outer PKCS#12 structure */

static int newpass_p12(PKCS12 *p12, char *oldpass, char *newpass)
{
    STACK_OF(PKCS7) * asafes, *newsafes;
    STACK_OF(PKCS12_SAFEBAG) * bags;
    int i, bagnid, pbe_nid = 0, pbe_iter = 0, pbe_saltlen = 0;
    PKCS7 *p7, *p7new;
    ASN1_OCTET_STRING *p12_data_tmp = NULL, *macnew = NULL;
    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;

    if (!(asafes = PKCS12_unpack_authsafes(p12)))
        return 0;
    if (!(newsafes = sk_PKCS7_new_null()))
        return 0;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, oldpass, -1);
            if (!alg_get(p7->d.encrypted->enc_data->algorithm,
                         &pbe_nid, &pbe_iter, &pbe_saltlen)) {
                sk_PKCS12_SAFEBAG_pop_free(bags,
                                           PKCS12_SAFEBAG_free);
                bags = NULL;
            }
        } else
            continue;
        if (bags == NULL)
            goto err;
        if (!newpass_bags(bags, oldpass, newpass)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto err;
        }
        /* Repack bag in same form with new password */
        if (bagnid == NID_pkcs7_data)
            p7new = PKCS12_pack_p7data(bags);
        else
            p7new = PKCS12_pack_p7encdata(pbe_nid, newpass, -1, NULL,
                                          pbe_saltlen, pbe_iter, bags);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        if (p7new == NULL)
            goto err;
        if (sk_PKCS7_push(newsafes, p7new) == 0)
            goto err;
    }
    sk_PKCS7_pop_free(asafes, PKCS7_free);

    /* Repack safe: save old safe in case of error */

    p12_data_tmp = p12->authsafes->d.data;
    if (!(p12->authsafes->d.data = ASN1_OCTET_STRING_new())) {
        p12->authsafes->d.data = p12_data_tmp;
        goto err;
    }
    if (!PKCS12_pack_authsafes(p12, newsafes))
        goto saferr;

    if (!PKCS12_gen_mac(p12, newpass, -1, mac, &maclen))
        goto saferr;
    if (!(macnew = ASN1_OCTET_STRING_new()))
        goto saferr;
    if (!ASN1_OCTET_STRING_set(macnew, mac, maclen))
        goto saferr;
    ASN1_OCTET_STRING_free(p12->mac->dinfo->digest);
    p12->mac->dinfo->digest = macnew;
    ASN1_OCTET_STRING_free(p12_data_tmp);

    return 1;

saferr:
    /* Restore old safe */
    ASN1_OCTET_STRING_free(p12->authsafes->d.data);
    ASN1_OCTET_STRING_free(macnew);
    p12->authsafes->d.data = p12_data_tmp;
    return 0;

err:
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    sk_PKCS7_pop_free(newsafes, PKCS7_free);
    return 0;
}

static int newpass_bags(STACK_OF(PKCS12_SAFEBAG) * bags, char *oldpass,
                        char *newpass)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!newpass_bag(sk_PKCS12_SAFEBAG_value(bags, i),
                         oldpass, newpass))
            return 0;
    }
    return 1;
}

/* Change password of safebag: only needs handle shrouded keybags */

static int newpass_bag(PKCS12_SAFEBAG *bag, char *oldpass, char *newpass)
{
    PKCS8_PRIV_KEY_INFO *p8;
    X509_SIG *p8new;
    int p8_nid, p8_saltlen, p8_iter;

    if (M_PKCS12_bag_type(bag) != NID_pkcs8ShroudedKeyBag)
        return 1;

    if (!(p8 = PKCS8_decrypt(bag->value.shkeybag, oldpass, -1)))
        return 0;
    if (!alg_get(bag->value.shkeybag->algor, &p8_nid, &p8_iter,
                 &p8_saltlen))
        return 0;
    if (!(p8new = PKCS8_encrypt(p8_nid, NULL, newpass, -1, NULL, p8_saltlen,
                                p8_iter, p8)))
        return 0;
    X509_SIG_free(bag->value.shkeybag);
    bag->value.shkeybag = p8new;
    return 1;
}

static int alg_get(X509_ALGOR *alg, int *pnid, int *piter, int *psaltlen)
{
    PBEPARAM *pbe;

    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), alg->parameter);
    if (!pbe)
        return 0;
    *pnid = OBJ_obj2nid(alg->algorithm);
    *piter = ASN1_INTEGER_get(pbe->iter);
    *psaltlen = pbe->salt->length;
    PBEPARAM_free(pbe);
    return 1;
}
