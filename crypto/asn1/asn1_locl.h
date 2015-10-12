/* asn1t.h */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Internal ASN1 structures and functions: not for application use */

char *gentime_string_from_tm(struct tm *tm);
char *utctime_string_from_tm(struct tm *tm);
int asn1_time_parse(const char *, size_t, struct tm *, int);

/* Method to handle CRL access.
 * In general a CRL could be very large (several Mb) and can consume large
 * amounts of resources if stored in memory by multiple processes.
 * This method allows general CRL operations to be redirected to more
 * efficient callbacks: for example a CRL entry database.
 */

#define X509_CRL_METHOD_DYNAMIC 1

struct x509_crl_method_st {
    int flags;
    int (*crl_init)(X509_CRL *crl);
    int (*crl_free)(X509_CRL *crl);
    int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret,
                      ASN1_INTEGER *ser, X509_NAME *issuer);
    int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk);
};

int asn1_get_choice_selector(ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_set_choice_selector(ASN1_VALUE **pval, int value, const ASN1_ITEM *it);

ASN1_VALUE **asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt, int nullerr);

int asn1_do_lock(ASN1_VALUE **pval, int op, const ASN1_ITEM *it);

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_enc_restore(int *len, uint8_t **out, ASN1_VALUE **pval, const ASN1_ITEM *it);
int asn1_enc_save(ASN1_VALUE **pval, const uint8_t *in, int inlen, const ASN1_ITEM *it);

void asn1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);

ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const uint8_t **pp, long length);
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a, uint8_t **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const uint8_t **pp, long length);
int i2c_ASN1_INTEGER(ASN1_INTEGER *a, uint8_t **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const uint8_t **pp, long length);
