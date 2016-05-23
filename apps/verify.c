/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

static int cb(int ok, X509_STORE_CTX *ctx);
static int check(X509_STORE *ctx, char *file, STACK_OF(X509) *uchain,
                 STACK_OF(X509) *tchain, STACK_OF(X509_CRL) *crls, ENGINE *e,
                 int show_chain);
static int v_verbose = 0, vflags = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_ENGINE,
    OPT_CAPATH,
    OPT_CAFILE,
    OPT_UNTRUSTED,
    OPT_TRUSTED,
    OPT_CRLFILE,
    OPT_SHOW_CHAIN,
    OPT_V_ENUM,
    OPT_VERBOSE
} OPTION_CHOICE;

OPTIONS verify_options[] = {
    { OPT_HELP_STR, 1, '-', "Usage: %s [options] cert.pem...\n" },
    { OPT_HELP_STR, 1, '-', "Valid options are:\n" },
    { "help", OPT_HELP, '-', "Display this summary" },
    { "verbose", OPT_VERBOSE, '-' },
    { "CApath", OPT_CAPATH, '/' },
    { "CAfile", OPT_CAFILE, '<' },
    { "untrusted", OPT_UNTRUSTED, '<' },
    { "trusted", OPT_TRUSTED, '<' },
    { "CRLfile", OPT_CRLFILE, '<' },
    { "show_chain", OPT_SHOW_CHAIN, '-' },
#ifndef OPENSSL_NO_ENGINE
    { "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
#endif
    OPT_V_OPTIONS,
    { NULL }
};

int verify_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    STACK_OF(X509) *untrusted = NULL, *trusted = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    char *prog, *CApath = NULL, *CAfile = NULL, *engine = NULL;
    char *untfile = NULL, *trustfile = NULL, *crlfile = NULL;
    int vpmtouched = 0, show_chain = 0, i = 0, ret = 1;
    OPTION_CHOICE o;

    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        goto end;

    prog = opt_init(argc, argv, verify_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(verify_options);
                BIO_printf(bio_err, "Recognized usages:\n");
                for (i = 0; i < X509_PURPOSE_get_count(); i++) {
                    X509_PURPOSE *ptmp;
                    ptmp = X509_PURPOSE_get0(i);
                    BIO_printf(bio_err, "\t%-10s\t%s\n", X509_PURPOSE_get0_sname(ptmp),
                               X509_PURPOSE_get0_name(ptmp));
                }
                ret = 0;
                goto end;
            case OPT_V_CASES:
                if (!opt_verify(o, vpm))
                    goto end;
                vpmtouched++;
                break;
            case OPT_CAPATH:
                CApath = opt_arg();
                break;
            case OPT_CAFILE:
                CAfile = opt_arg();
                break;
            case OPT_UNTRUSTED:
                untfile = opt_arg();
                break;
            case OPT_TRUSTED:
                trustfile = opt_arg();
                break;
            case OPT_CRLFILE:
                crlfile = opt_arg();
                break;
            case OPT_SHOW_CHAIN:
                show_chain = 1;
                break;
            case OPT_ENGINE:
                engine = opt_arg();
                break;
            case OPT_VERBOSE:
                v_verbose = 1;
                break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(engine, 0);
#endif
    if (!(store = setup_verify(CAfile, CApath)))
        goto end;
    X509_STORE_set_verify_cb(store, cb);

    if (vpmtouched)
        X509_STORE_set1_param(store, vpm);

    ERR_clear_error();

    if (untfile) {
        untrusted = load_certs(untfile, FORMAT_PEM, NULL, e, "untrusted certificates");
        if (!untrusted)
            goto end;
    }

    if (trustfile) {
        trusted = load_certs(trustfile, FORMAT_PEM, NULL, e, "trusted certificates");
        if (!trusted)
            goto end;
    }

    if (crlfile) {
        crls = load_crls(crlfile, FORMAT_PEM, NULL, e, "other CRLs");
        if (!crls)
            goto end;
    }

    ret = 0;
    if (argc < 1) {
        if (check(store, NULL, untrusted, trusted, crls, e, show_chain) != 1)
            ret = -1;
    } else {
        for (i = 0; i < argc; i++)
            if (check(store, argv[i], untrusted, trusted, crls, e, show_chain) != 1)
                ret = -1;
    }

end:
    X509_VERIFY_PARAM_free(vpm);
    X509_STORE_free(store);
    sk_X509_pop_free(untrusted, X509_free);
    sk_X509_pop_free(trusted, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return (ret < 0 ? 2 : ret);
}

static int check(X509_STORE *ctx, char *file, STACK_OF(X509) *uchain,
                 STACK_OF(X509) *tchain, STACK_OF(X509_CRL) *crls, ENGINE *e,
                 int show_chain)
{
    X509 *x = NULL;
    int i = 0, ret = 0;
    X509_STORE_CTX *csc;
    STACK_OF(X509) *chain = NULL;

    x = load_cert(file, FORMAT_PEM, NULL, e, "certificate file");
    if (x == NULL)
        goto end;
    printf("%s: ", (file == NULL) ? "stdin" : file);

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    X509_STORE_set_flags(ctx, vflags);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (tchain)
        X509_STORE_CTX_trusted_stack(csc, tchain);
    if (crls)
        X509_STORE_CTX_set0_crls(csc, crls);
    i = X509_verify_cert(csc);
    if (i > 0 && show_chain)
        chain = X509_STORE_CTX_get1_chain(csc);
    X509_STORE_CTX_free(csc);

    ret = 0;
end:
    if (i > 0) {
        printf("OK\n");
        ret = 1;
    } else
        ERR_print_errors(bio_err);
    if (chain) {
        printf("Chain:\n");
        for (i = 0; i < sk_X509_num(chain); i++) {
            X509 *cert = sk_X509_value(chain, i);
            printf("depth=%d: ", i);
            X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
            printf("\n");
        }
        sk_X509_pop_free(chain, X509_free);
    }
    X509_free(x);

    return (ret);
}

static int cb(int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        if (current_cert) {
            X509_NAME_print_ex_fp(stdout, X509_get_subject_name(current_cert), 0,
                                  XN_FLAG_ONELINE);
            printf("\n");
        }
        printf("%serror %d at %d depth lookup:%s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "", cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));
        switch (cert_error) {
            case X509_V_ERR_NO_EXPLICIT_POLICY:
                policies_print(bio_err, ctx);
            case X509_V_ERR_CERT_HAS_EXPIRED:

            /*
             * since we are just checking the certificates, it is ok if they
             * are self signed. But we should still warn the user.
             */

            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
            case X509_V_ERR_INVALID_CA:
            case X509_V_ERR_INVALID_NON_CA:
            case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_CRL_NOT_YET_VALID:
            case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                ok = 1;
        }

        return ok;
    }
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(bio_out, ctx);
    if (!v_verbose)
        ERR_clear_error();
    return (ok);
}
