/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <string.h>

static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
                            X509_STORE * st, unsigned long flags);
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID * id);
static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain, unsigned long flags);
static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID * *ret);
static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid, STACK_OF(OCSP_SINGLERESP) *sresp);
static int ocsp_check_delegated(X509 *x, int flags);
static int ocsp_req_find_signer(X509 **psigner, OCSP_REQUEST *req, X509_NAME *nm, STACK_OF(X509) *certs,
                                X509_STORE * st, unsigned long flags);

/* Verify a basic response message */

int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
                      X509_STORE * st, unsigned long flags)
{
    X509 *signer, *x;
    STACK_OF(X509) *chain = NULL;
    STACK_OF(X509) *tmpchain = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *tmpstore = NULL;
    X509_STORE_CTX ctx;
    int i, ret = 0;
    ret = ocsp_find_signer(&signer, bs, certs, st, flags);
    if (!ret) {
        OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
        goto end;
    }
    if ((ret == 2) && (flags & OCSP_TRUSTOTHER))
        chain = certs;
    if (!(flags & OCSP_NOSIGS)) {
        EVP_PKEY *skey;
        skey = X509_get_pubkey(signer);
        if (skey) {
            ret = OCSP_BASICRESP_verify(bs, skey, 0);
            EVP_PKEY_free(skey);
        }
        if (!skey || ret <= 0) {
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNATURE_FAILURE);
            goto end;
        }
    }
    if (!(flags & OCSP_NOVERIFY)) {
        int init_res;

        /*
         * If we trust the signer, we don't need to build a chain. (If the
         * signer is a root certificate, X509_verify_cert() would fail anyway!)
         */
        if (chain && chain == certs)
            goto verified_chain;

        /*
         * If we trust some "other" certificates, allow partial chains
         * (because some of them might be Intermediate CA Certificates),
         * put them in a store and attempt to build a trusted chain.
         */
        if ((flags & OCSP_TRUSTOTHER) && (certs != NULL)) {
            tmpstore = X509_STORE_new();
            if (tmpstore == NULL) {
                ret = -1;
                OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, ERR_R_MALLOC_FAILURE);
                goto end;
            }
            for (i = 0; i < sk_X509_num(certs); i++) {
                X509 *xother = sk_X509_value(certs, i);
                if (!X509_STORE_add_cert(tmpstore, xother)) {
                    ret = -1;
                    goto end;
                }
            }
            init_res = X509_STORE_CTX_init(&ctx, tmpstore, signer, NULL);
            if (!init_res) {
                ret = -1;
                OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, ERR_R_X509_LIB);
                goto end;
            }
            X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
            X509_STORE_CTX_set_flags(&ctx, X509_V_FLAG_PARTIAL_CHAIN);
            ret = X509_verify_cert(&ctx);
            if (ret == 1) {
                chain = tmpchain = X509_STORE_CTX_get1_chain(&ctx);
                X509_STORE_CTX_cleanup(&ctx);
                goto verified_chain;
            }
            X509_STORE_CTX_cleanup(&ctx);
        }

        /*
         * Attempt to build a chain up to a Root Certificate in the trust
         * store provided by the caller.
         */
        if (flags & OCSP_NOCHAIN) {
            untrusted = NULL;
        } else if (bs->certs && certs) {
            untrusted = sk_X509_dup(bs->certs);
            for (i = 0; i < sk_X509_num(certs); i++) {
                if (!sk_X509_push(untrusted, sk_X509_value(certs, i))) {
                    OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, ERR_R_MALLOC_FAILURE);
                    goto end;
                }
            }
        } else {
            untrusted = bs->certs;
        }
        init_res = X509_STORE_CTX_init(&ctx, st, signer, untrusted);
        if (!init_res) {
            ret = -1;
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, ERR_R_X509_LIB);
            goto end;
        }

        X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
        ret = X509_verify_cert(&ctx);
        chain = tmpchain = X509_STORE_CTX_get1_chain(&ctx);
        X509_STORE_CTX_cleanup(&ctx);
        if (ret <= 0) {
            i = X509_STORE_CTX_get_error(&ctx);
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_CERTIFICATE_VERIFY_ERROR);
            ERR_asprintf_error_data("Verify error: %s", X509_verify_cert_error_string(i));
            goto end;
        }

verified_chain:
        if (flags & OCSP_NOCHECKS) {
            ret = 1;
            goto end;
        }
        /* At this point we have a valid certificate chain
         * need to verify it against the OCSP issuer criteria.
         */
        ret = ocsp_check_issuer(bs, chain, flags);

        /* If fatal error or valid match then finish */
        if (ret != 0)
            goto end;

        /* Easy case: explicitly trusted. Get root CA and
         * check for explicit trust
         */
        if (flags & OCSP_NOEXPLICIT)
            goto end;

        x = sk_X509_value(chain, sk_X509_num(chain) - 1);
        if (X509_check_trust(x, NID_OCSP_sign, 0) != X509_TRUST_TRUSTED) {
            OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_ROOT_CA_NOT_TRUSTED);
            goto end;
        }
        ret = 1;
    }

end:
    sk_X509_pop_free(tmpchain, X509_free);
    X509_STORE_free(tmpstore);
    if (bs->certs && certs)
        sk_X509_free(untrusted);
    return ret;
}

static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
                            X509_STORE * st, unsigned long flags)
{
    X509 *signer;
    OCSP_RESPID *rid = bs->tbsResponseData->responderId;
    if ((signer = ocsp_find_signer_sk(certs, rid))) {
        *psigner = signer;
        return 2;
    }
    if (!(flags & OCSP_NOINTERN) && (signer = ocsp_find_signer_sk(bs->certs, rid))) {
        *psigner = signer;
        return 1;
    }
    /* Maybe lookup from store if by subject name */

    *psigner = NULL;
    return 0;
}

static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID * id)
{
    int i;
    uint8_t tmphash[SHA_DIGEST_LENGTH], *keyhash;
    X509 *x;

    /* Easy if lookup by name */
    if (id->type == V_OCSP_RESPID_NAME)
        return X509_find_by_subject(certs, id->value.byName);

    /* Lookup by key hash */

    /* If key hash isn't SHA1 length then forget it */
    if (id->value.byKey->length != SHA_DIGEST_LENGTH)
        return NULL;
    keyhash = id->value.byKey->data;
    /* Calculate hash of each key and compare */
    for (i = 0; i < sk_X509_num(certs); i++) {
        x = sk_X509_value(certs, i);
        X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
        if (!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
            return x;
    }
    return NULL;
}

static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain, unsigned long flags)
{
    STACK_OF(OCSP_SINGLERESP) *sresp;
    X509 *signer, *sca;
    OCSP_CERTID *caid = NULL;
    int i;
    sresp = bs->tbsResponseData->responses;

    if (sk_X509_num(chain) <= 0) {
        OCSPerr(OCSP_F_OCSP_CHECK_ISSUER, OCSP_R_NO_CERTIFICATES_IN_CHAIN);
        return -1;
    }

    /* See if the issuer IDs match. */
    i = ocsp_check_ids(sresp, &caid);

    /* If ID mismatch or other error then return */
    if (i <= 0)
        return i;

    signer = sk_X509_value(chain, 0);
    /* Check to see if OCSP responder CA matches request CA */
    if (sk_X509_num(chain) > 1) {
        sca = sk_X509_value(chain, 1);
        i = ocsp_match_issuerid(sca, caid, sresp);
        if (i < 0)
            return i;
        if (i) {
            /* We have a match, if extensions OK then success */
            if (ocsp_check_delegated(signer, flags))
                return 1;
            return 0;
        }
    }

    /* Otherwise check if OCSP request signed directly by request CA */
    return ocsp_match_issuerid(signer, caid, sresp);
}

/* Check the issuer certificate IDs for equality. If there is a mismatch with the same
 * algorithm then there's no point trying to match any certificates against the issuer.
 * If the issuer IDs all match then we just need to check equality against one of them.
 */

static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID * *ret)
{
    OCSP_CERTID *tmpid, *cid;
    int i, idcount;

    idcount = sk_OCSP_SINGLERESP_num(sresp);
    if (idcount <= 0) {
        OCSPerr(OCSP_F_OCSP_CHECK_IDS, OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA);
        return -1;
    }

    cid = sk_OCSP_SINGLERESP_value(sresp, 0)->certId;

    *ret = NULL;

    for (i = 1; i < idcount; i++) {
        tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
        /* Check to see if IDs match */
        if (OCSP_id_issuer_cmp(cid, tmpid)) {
            /* If algoritm mismatch let caller deal with it */
            if (OBJ_cmp(tmpid->hashAlgorithm->algorithm,
                        cid->hashAlgorithm->algorithm))
                return 2;
            /* Else mismatch */
            return 0;
        }
    }

    /* All IDs match: only need to check one ID */
    *ret = cid;
    return 1;
}

static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid,
                               STACK_OF(OCSP_SINGLERESP) *sresp)
{
    /* If only one ID to match then do it */
    if (cid) {
        const EVP_MD *dgst;
        X509_NAME *iname;
        int mdlen;
        uint8_t md[EVP_MAX_MD_SIZE];
        if (!(dgst = EVP_get_digestbyobj(cid->hashAlgorithm->algorithm))) {
            OCSPerr(OCSP_F_OCSP_MATCH_ISSUERID, OCSP_R_UNKNOWN_MESSAGE_DIGEST);
            return -1;
        }

        mdlen = EVP_MD_size(dgst);
        if (mdlen < 0)
            return -1;
        if ((cid->issuerNameHash->length != mdlen) || (cid->issuerKeyHash->length != mdlen))
            return 0;
        iname = X509_get_subject_name(cert);
        if (!X509_NAME_digest(iname, dgst, md, NULL))
            return -1;
        if (memcmp(md, cid->issuerNameHash->data, mdlen))
            return 0;
        X509_pubkey_digest(cert, dgst, md, NULL);
        if (memcmp(md, cid->issuerKeyHash->data, mdlen))
            return 0;

        return 1;

    } else {
        /* We have to match the whole lot */
        int i, ret;
        OCSP_CERTID *tmpid;
        for (i = 0; i < sk_OCSP_SINGLERESP_num(sresp); i++) {
            tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
            ret = ocsp_match_issuerid(cert, tmpid, NULL);
            if (ret <= 0)
                return ret;
        }
        return 1;
    }
}

static int ocsp_check_delegated(X509 *x, int flags)
{
    X509_check_purpose(x, -1, 0);
    if ((x->ex_flags & EXFLAG_XKUSAGE) && (x->ex_xkusage & XKU_OCSP_SIGN))
        return 1;
    OCSPerr(OCSP_F_OCSP_CHECK_DELEGATED, OCSP_R_MISSING_OCSPSIGNING_USAGE);
    return 0;
}

/* Verify an OCSP request. This is fortunately much easier than OCSP
 * response verify. Just find the signers certificate and verify it
 * against a given trust value.
 */

int OCSP_request_verify(OCSP_REQUEST *req, STACK_OF(X509) *certs, X509_STORE * store, unsigned long flags)
{
    X509 *signer;
    X509_NAME *nm;
    GENERAL_NAME *gen;
    int ret;
    X509_STORE_CTX ctx;
    if (!req->optionalSignature) {
        OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_REQUEST_NOT_SIGNED);
        return 0;
    }
    gen = req->tbsRequest->requestorName;
    if (!gen || gen->type != GEN_DIRNAME) {
        OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE);
        return 0;
    }
    nm = gen->d.directoryName;
    ret = ocsp_req_find_signer(&signer, req, nm, certs, store, flags);
    if (ret <= 0) {
        OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
        return 0;
    }
    if ((ret == 2) && (flags & OCSP_TRUSTOTHER))
        flags |= OCSP_NOVERIFY;
    if (!(flags & OCSP_NOSIGS)) {
        EVP_PKEY *skey;
        skey = X509_get_pubkey(signer);
        ret = OCSP_REQUEST_verify(req, skey);
        EVP_PKEY_free(skey);
        if (ret <= 0) {
            OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_SIGNATURE_FAILURE);
            return 0;
        }
    }
    if (!(flags & OCSP_NOVERIFY)) {
        int init_res;
        if (flags & OCSP_NOCHAIN)
            init_res = X509_STORE_CTX_init(&ctx, store, signer, NULL);
        else
            init_res = X509_STORE_CTX_init(&ctx, store, signer,
                                           req->optionalSignature->certs);
        if (!init_res) {
            OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, ERR_R_X509_LIB);
            return 0;
        }

        X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
        X509_STORE_CTX_set_trust(&ctx, X509_TRUST_OCSP_REQUEST);
        ret = X509_verify_cert(&ctx);
        X509_STORE_CTX_cleanup(&ctx);
        if (ret <= 0) {
            ret = X509_STORE_CTX_get_error(&ctx);
            OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_CERTIFICATE_VERIFY_ERROR);
            ERR_asprintf_error_data("Verify error:%s", X509_verify_cert_error_string(ret));
            return 0;
        }
    }
    return 1;
}

static int ocsp_req_find_signer(X509 **psigner, OCSP_REQUEST *req, X509_NAME *nm, STACK_OF(X509) *certs,
                                X509_STORE * st, unsigned long flags)
{
    X509 *signer;
    if (!(flags & OCSP_NOINTERN)) {
        signer = X509_find_by_subject(req->optionalSignature->certs, nm);
        if (signer) {
            *psigner = signer;
            return 1;
        }
    }

    signer = X509_find_by_subject(certs, nm);
    if (signer) {
        *psigner = signer;
        return 2;
    }
    return 0;
}
