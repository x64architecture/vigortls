/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST

#include <openssl/err.h>
#include <openssl/gost.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_GOST, func, 0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_GOST, 0, reason)

static ERR_STRING_DATA GOST_str_functs[] = {
    { ERR_FUNC(GOST_F_DECODE_GOST01_ALGOR_PARAMS),
     "DECODE_GOST01_ALGOR_PARAMS" },
    { ERR_FUNC(GOST_F_ENCODE_GOST01_ALGOR_PARAMS),
     "ENCODE_GOST01_ALGOR_PARAMS" },
    { ERR_FUNC(GOST_F_GOST2001_COMPUTE_PUBLIC), "GOST2001_COMPUTE_PUBLIC" },
    { ERR_FUNC(GOST_F_GOST2001_DO_SIGN), "GOST2001_DO_SIGN" },
    { ERR_FUNC(GOST_F_GOST2001_DO_VERIFY), "GOST2001_DO_VERIFY" },
    { ERR_FUNC(GOST_F_GOST2001_KEYGEN), "GOST2001_KEYGEN" },
    { ERR_FUNC(GOST_F_GOST89_GET_ASN1_PARAMETERS),
     "GOST89_GET_ASN1_PARAMETERS" },
    { ERR_FUNC(GOST_F_GOST89_SET_ASN1_PARAMETERS),
     "GOST89_SET_ASN1_PARAMETERS" },
    { ERR_FUNC(GOST_F_GOST_KEY_CHECK_KEY), "GOST_KEY_CHECK_KEY" },
    { ERR_FUNC(GOST_F_GOST_KEY_NEW), "GOST_KEY_NEW" },
    { ERR_FUNC(GOST_F_GOST_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES),
     "GOST_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES" },
    { ERR_FUNC(GOST_F_PARAM_COPY_GOST01), "PARAM_COPY_GOST01" },
    { ERR_FUNC(GOST_F_PARAM_DECODE_GOST01), "PARAM_DECODE_GOST01" },
    { ERR_FUNC(GOST_F_PKEY_GOST01_CTRL), "PKEY_GOST01_CTRL" },
    { ERR_FUNC(GOST_F_PKEY_GOST01_DECRYPT), "PKEY_GOST01_DECRYPT" },
    { ERR_FUNC(GOST_F_PKEY_GOST01_DERIVE), "PKEY_GOST01_DERIVE" },
    { ERR_FUNC(GOST_F_PKEY_GOST01_ENCRYPT), "PKEY_GOST01_ENCRYPT" },
    { ERR_FUNC(GOST_F_PKEY_GOST01_PARAMGEN), "PKEY_GOST01_PARAMGEN" },
    { ERR_FUNC(GOST_F_PKEY_GOST01_SIGN), "PKEY_GOST01_SIGN" },
    { ERR_FUNC(GOST_F_PKEY_GOST_MAC_CTRL), "PKEY_GOST_MAC_CTRL" },
    { ERR_FUNC(GOST_F_PKEY_GOST_MAC_KEYGEN), "PKEY_GOST_MAC_KEYGEN" },
    { ERR_FUNC(GOST_F_PRIV_DECODE_GOST01), "PRIV_DECODE_GOST01" },
    { ERR_FUNC(GOST_F_PUB_DECODE_GOST01), "PUB_DECODE_GOST01" },
    { ERR_FUNC(GOST_F_PUB_ENCODE_GOST01), "PUB_ENCODE_GOST01" },
    { ERR_FUNC(GOST_F_PUB_PRINT_GOST01), "PUB_PRINT_GOST01" },
    { ERR_FUNC(GOST_F_UNPACK_SIGNATURE_CP), "UNPACK_SIGNATURE_CP" },
    { ERR_FUNC(GOST_F_UNPACK_SIGNATURE_LE), "UNPACK_SIGNATURE_LE" },
    { 0, NULL }
};

static ERR_STRING_DATA GOST_str_reasons[] = {
    { ERR_REASON(GOST_R_BAD_KEY_PARAMETERS_FORMAT),
     "bad key parameters format" },
    { ERR_REASON(GOST_R_BAD_PKEY_PARAMETERS_FORMAT),
     "bad pkey parameters format" },
    { ERR_REASON(GOST_R_CANNOT_PACK_EPHEMERAL_KEY),
     "cannot pack ephemeral key" },
    { ERR_REASON(GOST_R_CTRL_CALL_FAILED), "ctrl call failed" },
    { ERR_REASON(GOST_R_ERROR_COMPUTING_SHARED_KEY),
     "error computing shared key" },
    { ERR_REASON(GOST_R_ERROR_PARSING_KEY_TRANSPORT_INFO),
     "error parsing key transport info" },
    { ERR_REASON(GOST_R_INCOMPATIBLE_ALGORITHMS), "incompatible algorithms" },
    { ERR_REASON(GOST_R_INCOMPATIBLE_PEER_KEY), "incompatible peer key" },
    { ERR_REASON(GOST_R_INVALID_DIGEST_TYPE), "invalid digest type" },
    { ERR_REASON(GOST_R_INVALID_IV_LENGTH), "invalid iv length" },
    { ERR_REASON(GOST_R_INVALID_MAC_KEY_LENGTH), "invalid mac key length" },
    { ERR_REASON(GOST_R_KEY_IS_NOT_INITIALIZED), "key is not initialized" },
    { ERR_REASON(GOST_R_KEY_PARAMETERS_MISSING), "key parameters missing" },
    { ERR_REASON(GOST_R_MAC_KEY_NOT_SET), "mac key not set" },
    { ERR_REASON(GOST_R_NO_PARAMETERS_SET), "no parameters set" },
    { ERR_REASON(GOST_R_NO_PEER_KEY), "no peer key" },
    { ERR_REASON(GOST_R_NO_PRIVATE_PART_OF_NON_EPHEMERAL_KEYPAIR),
     "no private part of non ephemeral keypair" },
    { ERR_REASON(GOST_R_PUBLIC_KEY_UNDEFINED), "public key undefined" },
    { ERR_REASON(GOST_R_RANDOM_GENERATOR_FAILURE), "random generator failure" },
    { ERR_REASON(GOST_R_RANDOM_NUMBER_GENERATOR_FAILED),
     "random number generator failed" },
    { ERR_REASON(GOST_R_SIGNATURE_MISMATCH), "signature mismatch" },
    { ERR_REASON(GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q),
     "signature parts greater than q" },
    { ERR_REASON(GOST_R_UKM_NOT_SET), "ukm not set" },
    { 0, NULL }
};

#endif

void ERR_load_GOST_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_func_error_string(GOST_str_functs[0].error) == NULL) {
        ERR_load_strings(0, GOST_str_functs);
        ERR_load_strings(0, GOST_str_reasons);
    }
#endif
}
#endif
