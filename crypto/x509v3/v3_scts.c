/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include "cryptlib.h"
#include "../ssl/ssl_locl.h"

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SCTS_TIMESTAMP unsigned __int64
#elif defined(__arch64__)
#define SCTS_TIMESTAMP unsigned long
#else
#define SCTS_TIMESTAMP unsigned long long
#endif

#define n2l8(c, l) (l = ((BN_ULLONG)(*((c)++))) << 56, \
    l |= ((SCTS_TIMESTAMP)(*((c)++))) << 48,           \
    l |= ((SCTS_TIMESTAMP)(*((c)++))) << 40,           \
    l |= ((SCTS_TIMESTAMP)(*((c)++))) << 32,           \
    l |= ((SCTS_TIMESTAMP)(*((c)++))) << 24,           \
    l |= ((SCTS_TIMESTAMP)(*((c)++))) << 16,           \
    l |= ((SCTS_TIMESTAMP)(*((c)++))) <<  8,           \
    l |= ((SCTS_TIMESTAMP)(*((c)++)))      )

static int i2r_scts(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *oct, BIO *out,
                    int indent);

const X509V3_EXT_METHOD v3_ct_scts[] = {
    {
        .ext_nid = NID_ct_precert_scts,
        .it = ASN1_ITEM_ref(ASN1_OCTET_STRING),
        .i2r = (X509V3_EXT_I2R)i2r_scts,
    },
    {
        .ext_nid = NID_ct_cert_scts,
        .it = ASN1_ITEM_ref(ASN1_OCTET_STRING),
        .i2r = (X509V3_EXT_I2R)i2r_scts,
    },
};

static void tls12_signature_print(BIO *out, const uint8_t *data)
{
    int nid = NID_undef;
    /* RFC6962 only permits two signature algorithms */
    if (data[0] == TLSEXT_hash_sha256) {
        if (data[1] == TLSEXT_signature_rsa)
            nid = NID_sha256WithRSAEncryption;
        else if (data[1] == TLSEXT_signature_ecdsa)
            nid = NID_ecdsa_with_SHA256;
    }
    if (nid == NID_undef)
        BIO_printf(out, "%02X%02X", data[0], data[1]);
    else
        BIO_printf(out, "%s", OBJ_nid2ln(nid));
}

static void timestamp_print(BIO *out, SCTS_TIMESTAMP timestamp)
{
    ASN1_GENERALIZEDTIME *gen;
    char genstr[20];
    gen = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME_adj(gen, (time_t)0, timestamp / 86400000,
                             (timestamp % 86400000) / 1000);
    /*
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     */
    snprintf(genstr, sizeof(genstr), "%.14s.%03dZ", ASN1_STRING_data(gen),
                 (unsigned int)(timestamp % 1000));
    ASN1_GENERALIZEDTIME_set_string(gen, genstr);
    ASN1_GENERALIZEDTIME_print(out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
}

static int i2r_scts(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *oct, BIO *out,
                    int indent)
{
    SCTS_TIMESTAMP timestamp;
    uint8_t *data = oct->data;
    unsigned short listlen, sctlen = 0, fieldlen;
    
    if (oct->length < 2)
        return 0;
    n2s(data, listlen);
    if (listlen != oct->length - 2)
        return 0;
    
    while (listlen > 0) {
        if (listlen < 2)
            return 0;
        n2s(data, sctlen);
        listlen -= 2;
        
        if ((sctlen < 1) || (sctlen > listlen))
            return 0;
        listlen -= sctlen;
        
        BIO_printf(out, "%*sSigned Certificate Timestamp:", indent, "");
        BIO_printf(out, "\n%*sVersion   : ", indent + 4, "");
        
        if (*data == 0) { /* SCT v1 */

            BIO_printf(out, "v1(0)");
            /*
             * Fixed-length header:
             *		        struct {
             * (1 byte)	      Version sct_version;
             * (32 bytes)	  LogID id;
             * (8 bytes)	  uint64 timestamp;
             * (2 bytes + ?)  CtExtensions extensions;
             */
            if (sctlen < 43)
                return 0;
            sctlen -= 43;
            
            BIO_printf(out, "\n%*sLog ID    : ", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, data + 1, 32);
            
            data += 33;
            n2l8(data, timestamp);
            BIO_printf(out, "\n%*sTimestamp : ", indent + 4, "");
            timestamp_print(out, timestamp);
            
            n2s(data, fieldlen);
            if (sctlen < fieldlen)
                return 0;
            sctlen -= fieldlen;
            BIO_printf(out, "\n%*sExtensions: ", indent + 4, "");
            if (fieldlen == 0)
                BIO_printf(out, "none");
            else
                BIO_hex_string(out, indent + 16, 16, data, fieldlen);
            data += fieldlen;
            
            /*
             * digitally-signed struct header:
             * (1 byte) Hash algorithm
             * (1 byte) Signature algorithm
             * (2 bytes + ?) Signature
             */
            if (sctlen < 4)
                return 0;
            sctlen -= 4;
            
            BIO_printf(out, "\n%*sSignature : ", indent + 4, "");
            tls12_signature_print(out, data);
            data += 2;
            n2s(data, fieldlen);
            if (sctlen != fieldlen)
                return 0;
            BIO_printf(out, "\n%*s            ", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, data, fieldlen);
            data += fieldlen;
        } else { /* Unknown version */
            BIO_printf(out, "unknown\n%*s", indent + 16, "");
            BIO_hex_string(out, indent + 16, 16, data, sctlen);
            data += sctlen;
        }
        if (listlen > 0)
            BIO_printf(out, "\n");
    }
    
    return 1;
}