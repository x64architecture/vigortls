/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdcompat.h>

static GENERAL_NAMES *v2i_subject_alt(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static GENERAL_NAMES *v2i_issuer_alt(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);
static int copy_email(X509V3_CTX *ctx, GENERAL_NAMES *gens, int move_p);
static int copy_issuer(X509V3_CTX *ctx, GENERAL_NAMES *gens);
static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);
static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx);

const X509V3_EXT_METHOD v3_alt[] = {
    { NID_subject_alt_name, 0, ASN1_ITEM_ref(GENERAL_NAMES),
      0, 0, 0, 0,
      0, 0,
      (X509V3_EXT_I2V)i2v_GENERAL_NAMES,
      (X509V3_EXT_V2I)v2i_subject_alt,
      NULL, NULL, NULL },

    { NID_issuer_alt_name, 0, ASN1_ITEM_ref(GENERAL_NAMES),
      0, 0, 0, 0,
      0, 0,
      (X509V3_EXT_I2V)i2v_GENERAL_NAMES,
      (X509V3_EXT_V2I)v2i_issuer_alt,
      NULL, NULL, NULL },

    { NID_certificate_issuer, 0, ASN1_ITEM_ref(GENERAL_NAMES),
      0, 0, 0, 0,
      0, 0,
      (X509V3_EXT_I2V)i2v_GENERAL_NAMES,
      NULL, NULL, NULL, NULL },
};

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
                                         GENERAL_NAMES *gens, STACK_OF(CONF_VALUE) *ret)
{
    int i;
    GENERAL_NAME *gen;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        ret = i2v_GENERAL_NAME(method, gen, ret);
    }
    if (!ret)
        return sk_CONF_VALUE_new_null();
    return ret;
}

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method,
                                        GENERAL_NAME *gen, STACK_OF(CONF_VALUE) *ret)
{
    uint8_t *p;
    char oline[256], htmp[5];
    int i;
    switch (gen->type) {
        case GEN_OTHERNAME:
            X509V3_add_value("othername", "<unsupported>", &ret);
            break;

        case GEN_X400:
            X509V3_add_value("X400Name", "<unsupported>", &ret);
            break;

        case GEN_EDIPARTY:
            X509V3_add_value("EdiPartyName", "<unsupported>", &ret);
            break;

        case GEN_EMAIL:
            X509V3_add_value_uchar("email", gen->d.ia5->data, &ret);
            break;

        case GEN_DNS:
            X509V3_add_value_uchar("DNS", gen->d.ia5->data, &ret);
            break;

        case GEN_URI:
            X509V3_add_value_uchar("URI", gen->d.ia5->data, &ret);
            break;

        case GEN_DIRNAME:
            X509_NAME_oneline(gen->d.dirn, oline, 256);
            X509V3_add_value("DirName", oline, &ret);
            break;

        case GEN_IPADD:
            p = gen->d.ip->data;
            if (gen->d.ip->length == 4)
                snprintf(oline, sizeof oline,
                         "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
            else if (gen->d.ip->length == 16) {
                oline[0] = 0;
                for (i = 0; i < 8; i++) {
                    snprintf(htmp, sizeof htmp,
                             "%X", p[0] << 8 | p[1]);
                    p += 2;
                    snprintf(oline, sizeof oline,
                        "%s%s", htmp, i != 7 ? ":" : "");
                }
            } else {
                X509V3_add_value("IP Address", "<invalid>", &ret);
                break;
            }
            X509V3_add_value("IP Address", oline, &ret);
            break;

        case GEN_RID:
            i2t_ASN1_OBJECT(oline, 256, gen->d.rid);
            X509V3_add_value("Registered ID", oline, &ret);
            break;
    }
    return ret;
}

int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen)
{
    uint8_t *p;
    int i;
    switch (gen->type) {
        case GEN_OTHERNAME:
            BIO_printf(out, "othername:<unsupported>");
            break;

        case GEN_X400:
            BIO_printf(out, "X400Name:<unsupported>");
            break;

        case GEN_EDIPARTY:
            /* Maybe fix this: it is supported now */
            BIO_printf(out, "EdiPartyName:<unsupported>");
            break;

        case GEN_EMAIL:
            BIO_printf(out, "email:%s", gen->d.ia5->data);
            break;

        case GEN_DNS:
            BIO_printf(out, "DNS:%s", gen->d.ia5->data);
            break;

        case GEN_URI:
            BIO_printf(out, "URI:%s", gen->d.ia5->data);
            break;

        case GEN_DIRNAME:
            BIO_printf(out, "DirName: ");
            X509_NAME_print_ex(out, gen->d.dirn, 0, XN_FLAG_ONELINE);
            break;

        case GEN_IPADD:
            p = gen->d.ip->data;
            if (gen->d.ip->length == 4)
                BIO_printf(out, "IP Address:%d.%d.%d.%d",
                           p[0], p[1], p[2], p[3]);
            else if (gen->d.ip->length == 16) {
                BIO_printf(out, "IP Address");
                for (i = 0; i < 8; i++) {
                    BIO_printf(out, ":%X", p[0] << 8 | p[1]);
                    p += 2;
                }
                BIO_puts(out, "\n");
            } else {
                BIO_printf(out, "IP Address:<invalid>");
                break;
            }
            break;

        case GEN_RID:
            BIO_printf(out, "Registered ID");
            i2a_ASN1_OBJECT(out, gen->d.rid);
            break;
    }
    return 1;
}

static GENERAL_NAMES *v2i_issuer_alt(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAMES *gens = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(gens = sk_GENERAL_NAME_new_null())) {
        X509V3err(X509V3_F_V2I_ISSUER_ALT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!name_cmp(cnf->name, "issuer") && cnf->value && strcmp(cnf->value, "copy") == 0) {
            if (!copy_issuer(ctx, gens))
                goto err;
        } else {
            GENERAL_NAME *gen;
            if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
                goto err;
            sk_GENERAL_NAME_push(gens, gen);
        }
    }
    return gens;
err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return NULL;
}

/* Append subject altname of issuer to issuer alt name of subject */

static int copy_issuer(X509V3_CTX *ctx, GENERAL_NAMES *gens)
{
    GENERAL_NAMES *ialt;
    GENERAL_NAME *gen;
    X509_EXTENSION *ext;
    int i;
    if (ctx && (ctx->flags == CTX_TEST))
        return 1;
    if (!ctx || !ctx->issuer_cert) {
        X509V3err(X509V3_F_COPY_ISSUER, X509V3_R_NO_ISSUER_DETAILS);
        goto err;
    }
    i = X509_get_ext_by_NID(ctx->issuer_cert, NID_subject_alt_name, -1);
    if (i < 0)
        return 1;
    if (!(ext = X509_get_ext(ctx->issuer_cert, i)) || !(ialt = X509V3_EXT_d2i(ext))) {
        X509V3err(X509V3_F_COPY_ISSUER, X509V3_R_ISSUER_DECODE_ERROR);
        goto err;
    }

    for (i = 0; i < sk_GENERAL_NAME_num(ialt); i++) {
        gen = sk_GENERAL_NAME_value(ialt, i);
        if (!sk_GENERAL_NAME_push(gens, gen)) {
            X509V3err(X509V3_F_COPY_ISSUER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    sk_GENERAL_NAME_free(ialt);

    return 1;

err:
    return 0;
}

static GENERAL_NAMES *v2i_subject_alt(X509V3_EXT_METHOD *method,
                                      X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAMES *gens = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(gens = sk_GENERAL_NAME_new_null())) {
        X509V3err(X509V3_F_V2I_SUBJECT_ALT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!name_cmp(cnf->name, "email") && cnf->value && strcmp(cnf->value, "copy") == 0) {
            if (!copy_email(ctx, gens, 0))
                goto err;
        } else if (!name_cmp(cnf->name, "email") && cnf->value && strcmp(cnf->value, "move") == 0) {
            if (!copy_email(ctx, gens, 1))
                goto err;
        } else {
            GENERAL_NAME *gen;
            if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
                goto err;
            sk_GENERAL_NAME_push(gens, gen);
        }
    }
    return gens;
err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return NULL;
}

/* Copy any email addresses in a certificate or request to
 * GENERAL_NAMES
 */

static int copy_email(X509V3_CTX *ctx, GENERAL_NAMES *gens, int move_p)
{
    X509_NAME *nm;
    ASN1_IA5STRING *email = NULL;
    X509_NAME_ENTRY *ne;
    GENERAL_NAME *gen = NULL;
    int i;
    if (ctx != NULL && ctx->flags == CTX_TEST)
        return 1;
    if (!ctx || (!ctx->subject_cert && !ctx->subject_req)) {
        X509V3err(X509V3_F_COPY_EMAIL, X509V3_R_NO_SUBJECT_DETAILS);
        goto err;
    }
    /* Find the subject name */
    if (ctx->subject_cert)
        nm = X509_get_subject_name(ctx->subject_cert);
    else
        nm = X509_REQ_get_subject_name(ctx->subject_req);

    /* Now add any email address(es) to STACK */
    i = -1;
    while ((i = X509_NAME_get_index_by_NID(nm,
                                           NID_pkcs9_emailAddress, i)) >= 0) {
        ne = X509_NAME_get_entry(nm, i);
        email = ASN1_STRING_dup(X509_NAME_ENTRY_get_data(ne));
        if (move_p) {
            X509_NAME_delete_entry(nm, i);
            X509_NAME_ENTRY_free(ne);
            i--;
        }
        if (!email || !(gen = GENERAL_NAME_new())) {
            X509V3err(X509V3_F_COPY_EMAIL, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        gen->d.ia5 = email;
        email = NULL;
        gen->type = GEN_EMAIL;
        if (!sk_GENERAL_NAME_push(gens, gen)) {
            X509V3err(X509V3_F_COPY_EMAIL, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        gen = NULL;
    }

    return 1;

err:
    GENERAL_NAME_free(gen);
    ASN1_IA5STRING_free(email);
    return 0;
}

GENERAL_NAMES *v2i_GENERAL_NAMES(const X509V3_EXT_METHOD *method,
                                 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAME *gen;
    GENERAL_NAMES *gens = NULL;
    CONF_VALUE *cnf;
    int i;
    if (!(gens = sk_GENERAL_NAME_new_null())) {
        X509V3err(X509V3_F_V2I_GENERAL_NAMES, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (!(gen = v2i_GENERAL_NAME(method, ctx, cnf)))
            goto err;
        sk_GENERAL_NAME_push(gens, gen);
    }
    return gens;
err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    return NULL;
}

GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                               CONF_VALUE *cnf)
{
    return v2i_GENERAL_NAME_ex(NULL, method, ctx, cnf, 0);
}

GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
                               const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                               int gen_type, char *value, int is_nc)
{
    char is_string = 0;
    GENERAL_NAME *gen = NULL;

    if (!value) {
        X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_MISSING_VALUE);
        return NULL;
    }

    if (out)
        gen = out;
    else {
        gen = GENERAL_NAME_new();
        if (gen == NULL) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }

    switch (gen_type) {
        case GEN_URI:
        case GEN_EMAIL:
        case GEN_DNS:
            is_string = 1;
            break;

        case GEN_RID: {
            ASN1_OBJECT *obj;
            if (!(obj = OBJ_txt2obj(value, 0))) {
                X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_BAD_OBJECT);
                ERR_asprintf_error_data("value=%s", value);
                goto err;
            }
            gen->d.rid = obj;
        } break;

        case GEN_IPADD:
            if (is_nc)
                gen->d.ip = a2i_IPADDRESS_NC(value);
            else
                gen->d.ip = a2i_IPADDRESS(value);
            if (gen->d.ip == NULL) {
                X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_BAD_IP_ADDRESS);
                ERR_asprintf_error_data("value=%s", value);
                goto err;
            }
            break;

        case GEN_DIRNAME:
            if (!do_dirname(gen, value, ctx)) {
                X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_DIRNAME_ERROR);
                goto err;
            }
            break;

        case GEN_OTHERNAME:
            if (!do_othername(gen, value, ctx)) {
                X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_OTHERNAME_ERROR);
                goto err;
            }
            break;
        default:
            X509V3err(X509V3_F_A2I_GENERAL_NAME, X509V3_R_UNSUPPORTED_TYPE);
            goto err;
    }

    if (is_string) {
        if (!(gen->d.ia5 = ASN1_IA5STRING_new()) || !ASN1_STRING_set(gen->d.ia5, (uint8_t *)value, strlen(value))) {
            X509V3err(X509V3_F_A2I_GENERAL_NAME, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    gen->type = gen_type;

    return gen;

err:
    if (!out)
        GENERAL_NAME_free(gen);
    return NULL;
}

GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,
                                  const X509V3_EXT_METHOD *method,
                                  X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc)
{
    int type;

    char *name, *value;

    name = cnf->name;
    value = cnf->value;

    if (!value) {
        X509V3err(X509V3_F_V2I_GENERAL_NAME_EX, X509V3_R_MISSING_VALUE);
        return NULL;
    }

    if (!name_cmp(name, "email"))
        type = GEN_EMAIL;
    else if (!name_cmp(name, "URI"))
        type = GEN_URI;
    else if (!name_cmp(name, "DNS"))
        type = GEN_DNS;
    else if (!name_cmp(name, "RID"))
        type = GEN_RID;
    else if (!name_cmp(name, "IP"))
        type = GEN_IPADD;
    else if (!name_cmp(name, "dirName"))
        type = GEN_DIRNAME;
    else if (!name_cmp(name, "otherName"))
        type = GEN_OTHERNAME;
    else {
        X509V3err(X509V3_F_V2I_GENERAL_NAME_EX, X509V3_R_UNSUPPORTED_OPTION);
        ERR_asprintf_error_data("name=%s", name);
        return NULL;
    }

    return a2i_GENERAL_NAME(out, method, ctx, type, value, is_nc);
}

static int do_othername(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx)
{
    char *objtmp = NULL, *p;
    int objlen;
    if (!(p = strchr(value, ';')))
        return 0;
    if (!(gen->d.otherName = OTHERNAME_new()))
        return 0;
    /* Free this up because we will overwrite it.
     * no need to free type_id because it is static
     */
    ASN1_TYPE_free(gen->d.otherName->value);
    if (!(gen->d.otherName->value = ASN1_generate_v3(p + 1, ctx)))
        return 0;
    objlen = p - value;
    objtmp = malloc(objlen + 1);
    if (objtmp == NULL)
        return 0;
    strlcpy(objtmp, value, objlen + 1);
    gen->d.otherName->type_id = OBJ_txt2obj(objtmp, 0);
    free(objtmp);
    if (!gen->d.otherName->type_id)
        return 0;
    return 1;
}

static int do_dirname(GENERAL_NAME *gen, char *value, X509V3_CTX *ctx)
{
    int ret;
    STACK_OF(CONF_VALUE) *sk;
    X509_NAME *nm;
    if (!(nm = X509_NAME_new()))
        return 0;
    sk = X509V3_get_section(ctx, value);
    if (!sk) {
        X509V3err(X509V3_F_DO_DIRNAME, X509V3_R_SECTION_NOT_FOUND);
        ERR_asprintf_error_data("section=%s", value);
        X509_NAME_free(nm);
        return 0;
    }
    /* FIXME: should allow other character types... */
    ret = X509V3_NAME_from_section(nm, sk, MBSTRING_ASC);
    if (!ret)
        X509_NAME_free(nm);
    gen->d.dirn = nm;
    X509V3_section_free(ctx, sk);

    return ret;
}
