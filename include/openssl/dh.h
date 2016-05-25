/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DH_H
#define HEADER_DH_H

#include <openssl/opensslconf.h>

#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/bn.h>
#endif

#include <openssl/threads.h>

#ifndef OPENSSL_DH_MAX_MODULUS_BITS
#define OPENSSL_DH_MAX_MODULUS_BITS 10000
#endif

#define DH_FLAG_CACHE_MONT_P 0x01
#define DH_FLAG_NO_EXP_CONSTTIME                        \
    0x02 /* new with 0.9.7h; the built-in DH            \
          * implementation now uses constant time       \
          * modular exponentiation for secret exponents \
          * by default. This flag causes the            \
          * faster variable sliding window method to    \
          * be used for all exponents.                  \
          */

#ifdef __cplusplus
extern "C" {
#endif

/* Already defined in ossl_typ.h */
/* typedef struct dh_st DH; */
/* typedef struct dh_method DH_METHOD; */

struct dh_method {
    const char *name;
    /* Methods here */
    int (*generate_key)(DH *dh);
    int (*compute_key)(uint8_t *key, const BIGNUM *pub_key, DH *dh);
    int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx,
                      BN_MONT_CTX *m_ctx); /* Can be null */

    int (*init)(DH *dh);
    int (*finish)(DH *dh);
    int flags;
    char *app_data;
    /* If this is non-NULL, it will be used to generate parameters */
    int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb);
};

struct dh_st {
    /* This first argument is used to pick up errors when
     * a DH is passed instead of a EVP_PKEY */
    int pad;
    int version;
    BIGNUM *p;
    BIGNUM *g;
    long length;      /* optional */
    BIGNUM *pub_key;  /* g^x */
    BIGNUM *priv_key; /* x */

    int flags;
    BN_MONT_CTX *method_mont_p;
    /* Place holders if we want to do X9.42 DH */
    BIGNUM *q;
    BIGNUM *j;
    uint8_t *seed;
    int seedlen;
    BIGNUM *counter;

    int references;
    CRYPTO_EX_DATA ex_data;
    const DH_METHOD *meth;
    ENGINE *engine;
    CRYPTO_MUTEX *lock;
};

#define DH_GENERATOR_2 2
/* #define DH_GENERATOR_3    3 */
#define DH_GENERATOR_5 5

/* DH_check error codes */
#define DH_CHECK_P_NOT_PRIME 0x01
#define DH_CHECK_P_NOT_SAFE_PRIME 0x02
#define DH_UNABLE_TO_CHECK_GENERATOR 0x04
#define DH_NOT_SUITABLE_GENERATOR 0x08

/* DH_check_pub_key error codes */
#define DH_CHECK_PUBKEY_TOO_SMALL 0x01
#define DH_CHECK_PUBKEY_TOO_LARGE 0x02

/* primes p where (p-1)/2 is prime too are called "safe"; we define
   this for backward compatibility: */
#define DH_CHECK_P_NOT_STRONG_PRIME DH_CHECK_P_NOT_SAFE_PRIME

#define d2i_DHparams_fp(fp, x)                                              \
    (DH *)ASN1_d2i_fp((char *(*)())DH_new, (char *(*)())d2i_DHparams, (fp), \
                      (uint8_t **)(x))
#define i2d_DHparams_fp(fp, x) ASN1_i2d_fp(i2d_DHparams, (fp), (uint8_t *)(x))
#define d2i_DHparams_bio(bp, x) ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)
#define i2d_DHparams_bio(bp, x) ASN1_i2d_bio_of_const(DH, i2d_DHparams, bp, x)

DH *DHparams_dup(DH *);

const DH_METHOD *DH_OpenSSL(void);

void DH_set_default_method(const DH_METHOD *meth);
const DH_METHOD *DH_get_default_method(void);
int DH_set_method(DH *dh, const DH_METHOD *meth);
DH *DH_new_method(ENGINE *engine);

DH *DH_new(void);
void DH_free(DH *dh);
int DH_up_ref(DH *dh);
int DH_size(const DH *dh);

/* DH_num_bits returns the minimum number of bits needed to represent the
 * absolute value of the DH group's prime. */
unsigned int DH_num_bits(const DH *dh);
int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DH_set_ex_data(DH *d, int idx, void *arg);
void *DH_get_ex_data(DH *d, int idx);

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED
DH *DH_generate_parameters(int prime_len, int generator,
                           void (*callback)(int, int, void *), void *cb_arg);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
int DH_generate_parameters_ex(DH *dh, int prime_len, int generator,
                              BN_GENCB *cb);

int DH_check(const DH *dh, int *codes);
int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *codes);
int DH_generate_key(DH *dh);
int DH_compute_key(uint8_t *key, const BIGNUM *pub_key, DH *dh);
DH *d2i_DHparams(DH **a, const uint8_t **pp, long length);
int i2d_DHparams(const DH *a, uint8_t **pp);
int DHparams_print_fp(FILE *fp, const DH *x);
int DHparams_print(BIO *bp, const DH *x);

/* RFC 5114 parameters */
DH *DH_get_1024_160(void);
DH *DH_get_2048_224(void);
DH *DH_get_2048_256(void);

#define EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len)      \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, NULL)

#define EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen)      \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                      EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL)

#define EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR (EVP_PKEY_ALG_CTRL + 2)

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_DH_strings(void);

/* Error codes for the DH functions. */

/* Function codes. */
# define DH_F_COMPUTE_KEY                                 102
# define DH_F_DHPARAMS_PRINT_FP                           101
# define DH_F_DH_BUILTIN_GENPARAMS                        106
# define DH_F_DH_COMPUTE_KEY                              114
# define DH_F_DH_GENERATE_KEY                             115
# define DH_F_DH_GENERATE_PARAMETERS_EX                   116
# define DH_F_DH_NEW_METHOD                               105
# define DH_F_DH_PARAM_DECODE                             107
# define DH_F_DH_PRIV_DECODE                              110
# define DH_F_DH_PRIV_ENCODE                              111
# define DH_F_DH_PUB_DECODE                               108
# define DH_F_DH_PUB_ENCODE                               109
# define DH_F_DO_DH_PRINT                                 100
# define DH_F_GENERATE_KEY                                103
# define DH_F_GENERATE_PARAMETERS                         104
# define DH_F_PKEY_DH_DERIVE                              112
# define DH_F_PKEY_DH_KEYGEN                              113

/* Reason codes. */
# define DH_R_BAD_GENERATOR                               101
# define DH_R_BN_DECODE_ERROR                             109
# define DH_R_BN_ERROR                                    106
# define DH_R_DECODE_ERROR                                104
# define DH_R_INVALID_PUBKEY                              102
# define DH_R_KEYS_NOT_SET                                108
# define DH_R_KEY_SIZE_TOO_SMALL                          110
# define DH_R_MODULUS_TOO_LARGE                           103
# define DH_R_NO_PARAMETERS_SET                           107
# define DH_R_NO_PRIVATE_VALUE                            100
# define DH_R_PARAMETER_ENCODING_ERROR                    105

#ifdef  __cplusplus
}
#endif
#endif
