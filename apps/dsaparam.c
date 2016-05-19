/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h> /* for OPENSSL_NO_DSA */

#ifndef OPENSSL_NO_DSA
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#ifdef GENCB_TEST

static int stop_keygen_flag = 0;

static void timebomb_sigalarm(int foo)
{
    stop_keygen_flag = 1;
}

#endif

static int dsa_cb(int p, int n, BN_GENCB *cb);

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_INFORM,
    OPT_OUTFORM,
    OPT_IN,
    OPT_OUT,
    OPT_TEXT,
    OPT_C,
    OPT_NOOUT,
    OPT_GENKEY,
    OPT_ENGINE,
    OPT_TIMEBOMB
} OPTION_CHOICE;

OPTIONS dsaparam_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },
    { "inform", OPT_INFORM, 'F', "Input format - DER or PEM" },
    { "in", OPT_IN, '<', "Input file" },
    { "outform", OPT_OUTFORM, 'F', "Output format - DER or PEM" },
    { "out", OPT_OUT, '>', "Output file" },
    { "text", OPT_TEXT, '-', "Print as text" },
    { "C", OPT_C, '-', "Output C code" },
    { "noout", OPT_NOOUT, '-', "No output" },
    { "genkey", OPT_GENKEY, '-', "Generate a DSA key" },
#ifndef OPENSSL_NO_ENGINE
    { "engine", OPT_ENGINE, 's', "Use engine e, possibly a hardware device" },
#endif
#ifdef GENCB_TEST
    { "timebomb", OPT_TIMEBOMB, 'p', "Interrupt keygen after 'pnum' seconds" },
#endif
    { NULL }
};

int dsaparam_main(int argc, char **argv)
{
    DSA *dsa = NULL;
    BIO *in = NULL, *out = NULL;
    BN_GENCB cb;
    int numbits = -1, num, genkey = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, noout = 0, C = 0, ret = 1;
    int i, text = 0;
#ifdef GENCB_TEST
    int timebomb = 0;
#endif
    char *infile = NULL, *outfile = NULL, *prog, *engine = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, dsaparam_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
            opthelp:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(dsaparam_options);
                ret = 0;
                goto end;
            case OPT_INFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                    goto opthelp;
                break;
            case OPT_IN:
                infile = opt_arg();
                break;
            case OPT_OUTFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                    goto opthelp;
                break;
            case OPT_OUT:
                outfile = opt_arg();
                break;
            case OPT_ENGINE:
                engine = opt_arg();
                break;
            case OPT_TIMEBOMB:
#ifdef GENCB_TEST
                timebomb = atoi(opt_arg());
                break;
#endif
            case OPT_TEXT:
                text = 1;
                break;
            case OPT_C:
                C = 1;
                break;
            case OPT_GENKEY:
                genkey = 1;
                break;
            case OPT_NOOUT:
                noout = 1;
                break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (argc == 1) {
        if (!opt_int(argv[0], &num))
            goto end;
        /* generate a key */
        numbits = num;
    }

    in = bio_open_default(infile, "r");
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, "w");
    if (out == NULL)
        goto end;

#ifndef OPENSSL_NO_ENGINE
    setup_engine(engine, 0);
#endif

    if (numbits > 0) {
        BN_GENCB_set(&cb, dsa_cb, bio_err);
        dsa = DSA_new();
        if (!dsa) {
            BIO_printf(bio_err, "Error allocating DSA object\n");
            goto end;
        }
        BIO_printf(bio_err, "Generating DSA parameters, %d bit long prime\n", num);
        BIO_printf(bio_err, "This could take some time\n");
#ifdef GENCB_TEST
        if (timebomb > 0) {
            struct sigaction act;
            act.sa_handler = timebomb_sigalarm;
            act.sa_flags = 0;
            BIO_printf(bio_err, "(though I'll stop it if not done within %d secs)\n",
                       timebomb);
            if (sigaction(SIGALRM, &act, NULL) != 0) {
                BIO_printf(bio_err, "Error, couldn't set SIGALRM handler\n");
                goto end;
            }
            alarm(timebomb);
        }
#endif
        if (!DSA_generate_parameters_ex(dsa, num, NULL, 0, NULL, NULL, &cb)) {
#ifdef GENCB_TEST
            if (stop_keygen_flag) {
                BIO_printf(bio_err, "DSA key generation time-stopped\n");
                /* This is an asked-for behaviour! */
                ret = 0;
                goto end;
            }
#endif
            ERR_print_errors(bio_err);
            BIO_printf(bio_err, "Error, DSA key generation failed\n");
            goto end;
        }
    } else if (informat == FORMAT_ASN1)
        dsa = d2i_DSAparams_bio(in, NULL);
    else
        dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL);
    if (dsa == NULL) {
        BIO_printf(bio_err, "unable to load DSA parameters\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (text) {
        DSAparams_print(out, dsa);
    }

    if (C) {
        uint8_t *data;
        int len, bits_p;

        len = BN_num_bytes(dsa->p);
        bits_p = BN_num_bits(dsa->p);
        data = malloc(len + 20);
        if (data == NULL) {
            perror("malloc failure");
            goto end;
        }

        BIO_printf(bio_out, "DSA *get_dsa%d()\n{\n", bits_p);
        print_bignum_var(bio_out, dsa->p, "dsap", len, data);
        print_bignum_var(bio_out, dsa->q, "dsaq", len, data);
        print_bignum_var(bio_out, dsa->g, "dsag", len, data);
        BIO_printf(bio_out, "    DSA *dsa = DSA_new();\n"
                            "\n");
        BIO_printf(bio_out, "    if (dsa == NULL)\n"
                            "        return NULL;\n");
        BIO_printf(bio_out, "    dsa->p = BN_bin2bn(dsap_%d, sizeof (dsap_%d), NULL);\n",
                   bits_p, bits_p);
        BIO_printf(bio_out, "    dsa->q = BN_bin2bn(dsaq_%d, sizeof (dsaq_%d), NULL);\n",
                   bits_p, bits_p);
        BIO_printf(bio_out, "    dsa->g = BN_bin2bn(dsag_%d, sizeof (dsag_%d), NULL);\n",
                   bits_p, bits_p);
        BIO_printf(bio_out, "    if (!dsa->p || !dsa->q || !dsa->g) {\n"
                            "        DSA_free(dsa);\n"
                            "        return NULL;\n"
                            "    }\n"
                            "    return(dsa);\n}\n");
        free(data);
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_DSAparams_bio(out, dsa);
        else
            i = PEM_write_bio_DSAparams(out, dsa);
        if (!i) {
            BIO_printf(bio_err, "unable to write DSA parameters\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (genkey) {
        DSA *dsakey;

        if ((dsakey = DSAparams_dup(dsa)) == NULL)
            goto end;
        if (!DSA_generate_key(dsakey)) {
            ERR_print_errors(bio_err);
            DSA_free(dsakey);
            goto end;
        }
        if (outformat == FORMAT_ASN1)
            i = i2d_DSAPrivateKey_bio(out, dsakey);
        else
            i = PEM_write_bio_DSAPrivateKey(out, dsakey, NULL, NULL, 0, NULL, NULL);
        DSA_free(dsakey);
    }
    ret = 0;
end:
    BIO_free(in);
    BIO_free_all(out);
    DSA_free(dsa);
    return (ret);
}

static int dsa_cb(int p, int n, BN_GENCB *cb)
{
    char c;

    select_symbol(p, &c);
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);
#ifdef GENCB_TEST
    if (stop_keygen_flag)
        return 0;
#endif
    return 1;
}

#endif
