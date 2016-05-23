/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <openssl/opensslconf.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/lhash.h>
#include <openssl/bn.h>
#define USE_SOCKETS
#include "apps.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <stdcompat.h>
#include "s_apps.h"
#include "timeouts.h"

static RSA *tmp_rsa_cb(SSL *s, int is_export, int keylength);
static int sv_body(char *hostname, int s, uint8_t *context);
static int www_body(char *hostname, int s, uint8_t *context);
static void close_accept_socket(void);
static int init_ssl_connection(SSL *s);
static void print_stats(BIO *bp, SSL_CTX *ctx);
static int generate_session_id(const SSL *ssl, uint8_t *id,
                               unsigned int *id_len);
static DH *load_dh_param(const char *dhfile);
static DH *get_dh512(void);

static uint8_t dh512_p[] = {
    0xDA, 0x58, 0x3C, 0x16, 0xD9, 0x85, 0x22, 0x89, 0xD0, 0xE4, 0xAF, 0x75,
    0x6F, 0x4C, 0xCA, 0x92, 0xDD, 0x4B, 0xE5, 0x33, 0xB8, 0x04, 0xFB, 0x0F,
    0xED, 0x94, 0xEF, 0x9C, 0x8A, 0x44, 0x03, 0xED, 0x57, 0x46, 0x50, 0xD3,
    0x69, 0x99, 0xDB, 0x29, 0xD7, 0x76, 0x27, 0x6B, 0xA2, 0xD3, 0xD4, 0x12,
    0xE2, 0x18, 0xF4, 0xDD, 0x1E, 0x08, 0x4C, 0xF6, 0xD8, 0x00, 0x3E, 0x7C,
    0x47, 0x74, 0xE8, 0x33,
};
static uint8_t dh512_g[] = {
    0x02,
};

static DH *get_dh512(void)
{
    DH *dh = NULL;

    if ((dh = DH_new()) == NULL)
        return (NULL);
    dh->p = BN_bin2bn(dh512_p, sizeof(dh512_p), NULL);
    dh->g = BN_bin2bn(dh512_g, sizeof(dh512_g), NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
        return (NULL);
    return (dh);
}

/* static int load_CA(SSL_CTX *ctx, char *file);*/

#undef BUFSIZZ
#define BUFSIZZ 16 * 1024
static int bufsize = BUFSIZZ;
static int accept_socket = -1;

#define TEST_CERT "server.pem"
#define TEST_CERT2 "server2.pem"

extern int verify_depth, verify_return_error;

static char *cipher = NULL;
static int s_server_verify = SSL_VERIFY_NONE;
static int s_server_session_id_context = 1; /* anything will do */
static const char *s_cert_file = TEST_CERT, *s_key_file = NULL;
static const char *s_cert_file2 = TEST_CERT2, *s_key_file2 = NULL;
static char *s_dcert_file = NULL, *s_dkey_file = NULL;
static int s_nbio = 0;
int s_crlf = 0;
static SSL_CTX *ctx = NULL;
static SSL_CTX *ctx2 = NULL;
static int www = 0;

static BIO *bio_s_out = NULL;
static BIO *bio_s_msg = NULL;
static int s_debug = 0;
static int s_tlsextdebug = 0;
static int s_tlsextstatus = 0;
static int cert_status_cb(SSL *s, void *arg);
static int s_msg = 0;
static int s_quiet = 0;

static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

#ifndef OPENSSL_NO_ENGINE
static char *engine_id = NULL;
#endif
static const char *session_id_prefix = NULL;

static int enable_timeouts = 0;
static long socket_mtu;
#ifndef OPENSSL_NO_DTLS1
static int cert_chain = 0;
#endif

static int local_argc = 0;
static char **local_argv;

static void s_server_init(void)
{
    accept_socket = -1;
    cipher = NULL;
    s_server_verify = SSL_VERIFY_NONE;
    s_dcert_file = NULL;
    s_dkey_file = NULL;
    s_cert_file = TEST_CERT;
    s_key_file = NULL;
    s_cert_file2 = TEST_CERT2;
    s_key_file2 = NULL;
    ctx2 = NULL;
    s_nbio = 0;
    ctx = NULL;
    www = 0;

    bio_s_out = NULL;
    s_debug = 0;
    s_msg = 0;
    s_quiet = 0;
#ifndef OPENSSL_NO_ENGINE
    engine_id = NULL;
#endif
}

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    char *servername;
    BIO *biodebug;
    int extension_error;
} tlsextctx;

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *)arg;
    const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (servername && p->biodebug)
        BIO_printf(p->biodebug, "Hostname in TLS extension: \"%s\"\n", servername);

    if (!p->servername)
        return SSL_TLSEXT_ERR_NOACK;

    if (servername) {
        if (strcmp(servername, p->servername))
            return p->extension_error;
        if (ctx2) {
            BIO_printf(p->biodebug, "Switching server context.\n");
            SSL_set_SSL_CTX(s, ctx2);
        }
    }
    return SSL_TLSEXT_ERR_OK;
}

/* Structure passed to cert status callback */

typedef struct tlsextstatusctx_st {
    /* Default responder to use */
    char *host, *path, *port;
    int use_ssl;
    int timeout;
    BIO *err;
    int verbose;
} tlsextstatusctx;

static tlsextstatusctx tlscstatp = { NULL, NULL, NULL, 0, -1, NULL, 0 };

/* Certificate Status callback. This is called when a client includes a
 * certificate status request extension.
 *
 * This is a simplified version. It examines certificates each time and
 * makes one OCSP responder query for each request.
 *
 * A full version would store details such as the OCSP certificate IDs and
 * minimise the number of OCSP responses by caching them until they were
 * considered "expired".
 */

static int cert_status_cb(SSL *s, void *arg)
{
    tlsextstatusctx *srctx = arg;
    BIO *err = srctx->err;
    char *host, *port, *path;
    int use_ssl;
    uint8_t *rspder = NULL;
    int rspderlen;
    STACK_OF(OPENSSL_STRING) *aia = NULL;
    X509 *x = NULL;
    X509_STORE_CTX inctx;
    X509_OBJECT obj;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_CERTID *id = NULL;
    STACK_OF(X509_EXTENSION) *exts;
    int ret = SSL_TLSEXT_ERR_NOACK;
    int i;

    if (srctx->verbose)
        BIO_puts(err, "cert_status: callback called\n");
    /* Build up OCSP query from server certificate */
    x = SSL_get_certificate(s);
    aia = X509_get1_ocsp(x);
    if (aia) {
        if (!OCSP_parse_url(sk_OPENSSL_STRING_value(aia, 0),
                            &host, &port, &path, &use_ssl)) {
            BIO_puts(err, "cert_status: can't parse AIA URL\n");
            goto err;
        }
        if (srctx->verbose)
            BIO_printf(err, "cert_status: AIA URL: %s\n",
                       sk_OPENSSL_STRING_value(aia, 0));
    } else {
        if (!srctx->host) {
            BIO_puts(srctx->err, "cert_status: no AIA and no default responder URL\n");
            goto done;
        }
        host = srctx->host;
        path = srctx->path;
        port = srctx->port;
        use_ssl = srctx->use_ssl;
    }

    if (!X509_STORE_CTX_init(&inctx,
                             SSL_CTX_get_cert_store(SSL_get_SSL_CTX(s)),
                             NULL, NULL))
        goto err;
    if (X509_STORE_get_by_subject(&inctx, X509_LU_X509,
                                  X509_get_issuer_name(x), &obj) <= 0) {
        BIO_puts(err, "cert_status: Can't retrieve issuer certificate.\n");
        X509_STORE_CTX_cleanup(&inctx);
        goto done;
    }
    req = OCSP_REQUEST_new();
    if (!req)
        goto err;
    id = OCSP_cert_to_id(NULL, x, obj.data.x509);
    X509_free(obj.data.x509);
    X509_STORE_CTX_cleanup(&inctx);
    if (!id)
        goto err;
    if (!OCSP_request_add0_id(req, id))
        goto err;
    id = NULL;
    /* Add any extensions to the request */
    SSL_get_tlsext_status_exts(s, &exts);
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        if (!OCSP_REQUEST_add_ext(req, ext, -1))
            goto err;
    }
    resp = process_responder(req, host, path, port, use_ssl, NULL,
                             srctx->timeout);
    if (!resp) {
        BIO_puts(err, "cert_status: error querying responder\n");
        goto done;
    }
    rspderlen = i2d_OCSP_RESPONSE(resp, &rspder);
    if (rspderlen <= 0)
        goto err;
    SSL_set_tlsext_status_ocsp_resp(s, rspder, rspderlen);
    if (srctx->verbose) {
        BIO_puts(err, "cert_status: ocsp response sent:\n");
        OCSP_RESPONSE_print(err, resp, 2);
    }
    ret = SSL_TLSEXT_ERR_OK;
done:
    if (ret != SSL_TLSEXT_ERR_OK)
        ERR_print_errors(err);
    if (aia) {
        free(host);
        free(path);
        free(port);
        X509_email_free(aia);
    }
    if (id)
        OCSP_CERTID_free(id);
    if (req)
        OCSP_REQUEST_free(req);
    if (resp)
        OCSP_RESPONSE_free(resp);
    return ret;
err:
    ret = SSL_TLSEXT_ERR_ALERT_FATAL;
    goto done;
}

/* This is the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    uint8_t *data;
    unsigned int len;
} tlsextnextprotoctx;

static int next_proto_cb(SSL *s, const uint8_t **data, unsigned int *len, void *arg)
{
    tlsextnextprotoctx *next_proto = arg;

    *data = next_proto->data;
    *len = next_proto->len;

    return SSL_TLSEXT_ERR_OK;
}

typedef struct tlsextalpnctx_st {
    uint8_t *data;
    unsigned int len;
} tlsextalpnctx;

static int alpn_cb(SSL *s, const uint8_t **out, uint8_t *outlen,
                   const uint8_t *in, unsigned int inlen, void *arg)
{
    tlsextalpnctx *alpn_ctx = arg;

    if (!s_quiet) {
        /* We cam assume that in is syntactically valid. */
        unsigned int i;

        BIO_printf(bio_s_out, "ALPN protocols advertised by the client: ");
        for (i = 0; i < inlen; ) {
            if (i)
                BIO_write(bio_s_out, ", ", 2);
            BIO_write(bio_s_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_s_out, "\n", 1);
    }

    if (SSL_select_next_proto((uint8_t**)out, outlen, alpn_ctx->data,
        alpn_ctx->len, in, inlen) != OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_NOACK;

    if (!s_quiet) {
        BIO_printf(bio_s_out, "ALPN protocols selected: ");
        BIO_write(bio_s_out, *out, *outlen);
        BIO_write(bio_s_out, "\n", 1);
    }

    return SSL_TLSEXT_ERR_OK;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_ENGINE,
    OPT_PORT,
    OPT_VERIFY,
    OPT_UPPER_V_VERIFY,
    OPT_CONTEXT,
    OPT_CERT,
    OPT_CERTFORM,
    OPT_KEY,
    OPT_KEYFORM,
    OPT_PASS,
    OPT_DHPARAM,
    OPT_DCERTFORM,
    OPT_DCERT,
    OPT_DKEYFORM,
    OPT_DPASS,
    OPT_DKEY,
    OPT_NOCERT,
    OPT_CAPATH,
    OPT_NO_CACHE,
    OPT_VERIFY_RET_ERROR,
    OPT_CAFILE,
    OPT_NBIO,
    OPT_DEBUG,
    OPT_TLSEXTDEBUG,
    OPT_STATUS,
    OPT_STATUS_VERBOSE,
    OPT_STATUS_TIMEOUT,
    OPT_STATUS_URL,
    OPT_MSG,
    OPT_MSGFILE,
    OPT_STATE,
    OPT_CRLF,
    OPT_QUIET,
    OPT_NO_TMP_RSA,
    OPT_NO_DHE,
    OPT_NO_ECDHE,
    OPT_WWW,
    OPT_UPPER_WWW,
    OPT_HTTP,
    OPT_TLS1_2,
    OPT_TLS1_1,
    OPT_TLS1,
    OPT_DTLS1,
    OPT_TIMEOUT,
    OPT_MTU,
    OPT_CHAIN,
    OPT_ID_PREFIX,
    OPT_SERVERNAME,
    OPT_SERVERNAME_FATAL,
    OPT_CERT2,
    OPT_KEY2,
    OPT_NEXTPROTONEG,
    OPT_ALPN,
    OPT_KEYMATEXPORT,
    OPT_KEYMATEXPORTLEN,
    OPT_S_ENUM,
    OPT_V_ENUM,
} OPTION_CHOICE;

OPTIONS s_server_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },

    { "port", OPT_PORT, 'p' },
    { "accept", OPT_PORT, 'p', "TCP/IP port to accept on (default is " PORT_STR ")" },
    { "context", OPT_CONTEXT, 's', "Set session ID context" },
    { "verify", OPT_VERIFY, 'n', "Turn on peer certificate verification" },
    { "Verify", OPT_UPPER_V_VERIFY, 'n',
      "Turn on peer certificate verification, must have a cert" },
    { "cert", OPT_CERT, '<', "Certificate file to use; default is " TEST_CERT },
    { "certform", OPT_CERTFORM, 'F', "Certificate format (PEM or DER) PEM default" },
    { "key", OPT_KEY, '<', "Private Key if not in -cert; default is " TEST_CERT },
    { "keyform", OPT_KEYFORM, 'f', "Key format (PEM, DER or ENGINE) PEM default" },
    { "pass", OPT_PASS, 's', "Private key file pass phrase source" },
    { "dcert", OPT_DCERT, '<', "Second certificate file to use (usually for DSA)" },
    { "dcertform", OPT_DCERTFORM, 'F',
      "Second certificate format (PEM or DER) PEM default" },
    { "dkey", OPT_DKEY, '<', "Second private key file to use (usually for DSA)" },
    { "dkeyform", OPT_DKEYFORM, 'F', "Second key format (PEM, DER or ENGINE) PEM default" },
    { "dpass", OPT_DPASS, 's', "Second private key file pass phrase source" },
    { "nbio", OPT_NBIO, '-', "Use non-blocking IO" },
    { "crlf", OPT_CRLF, '-', "Convert LF from terminal into CRLF" },
    { "debug", OPT_DEBUG, '-', "Print more output" },
    { "msg", OPT_MSG, '-', "Show protocol messages" },
    { "msgfile", OPT_MSGFILE, '>' },
    { "state", OPT_STATE, '-', "Print the SSL states" },
    { "CApath", OPT_CAPATH, '/', "PEM format directory of CA's" },
    { "CAfile", OPT_CAFILE, '<', "PEM format file of CA's" },
    { "nocert", OPT_NOCERT, '-', "Don't use any certificates (Anon-DH)" },
    { "quiet", OPT_QUIET, '-', "No server output" },
    { "no_tmp_rsa", OPT_NO_TMP_RSA, '-', "Do not generate a tmp RSA key" },
    { "tls1_2", OPT_TLS1_2, '-', "just talk TLSv1.2" },
    { "tls1_1", OPT_TLS1_1, '-', "Just talk TLSv1.1" },
    { "tls1", OPT_TLS1, '-', "Just talk TLSv1" },
#ifndef OPENSSL_NO_DTLS1
    { "dtls1", OPT_DTLS1, '-', "Just talk DTLSv1" },
    { "timeout", OPT_TIMEOUT, '-', "Enable timeouts" },
    { "mtu", OPT_MTU, 'p', "Set link layer MTU" },
#endif
#ifndef OPENSSL_NO_DH
    { "no_dhe", OPT_NO_DHE, '-', "Disable ephemeral DH" },
#endif
    { "no_ecdhe", OPT_NO_ECDHE, '-', "Disable ephemeral ECDH" },
    { "www", OPT_WWW, '-', "Respond to a 'GET /' with a status page" },
    { "WWW", OPT_UPPER_WWW, '-', "Respond to a 'GET with the file ./path" },
    { "HTTP", OPT_HTTP, '-', "Like -WWW but ./path incluedes HTTP headers" },
    { "id_prefix", OPT_ID_PREFIX, 's', "Generate SSL/TLS session IDs prefixed by arg" },
    { "servername", OPT_SERVERNAME, 's', "Servername for HostName TLS extension" },
    { "servername_fatal", OPT_SERVERNAME_FATAL, '-',
      "mismatch send fatal alert (default warning alert)" },
    { "cert2", OPT_CERT2, '<',
      "Certificate file to use for servername; default is" TEST_CERT2 },
    { "key2", OPT_KEY2, '<', "-Private Key file to use for servername if not in -cert2" },
    { "tlsextdebug", OPT_TLSEXTDEBUG, '-', "Hex dump of all TLS extensions received" },
    { "nextprotoneg", OPT_NEXTPROTONEG, 's', "Set the advertised protocols for "
                                             "the NPN extension "
                                             "(comma-separated list)" },
    { "alpn", OPT_ALPN, 's', "Set the advertised protocols for the ALPN "
                             "extension (comma-separated list)" },
    { "keymatexport", OPT_KEYMATEXPORT, 's', "Export keying material using label" },
    { "keymatexportlen", OPT_KEYMATEXPORTLEN, 'p',
      "Export len bytes of keying material (default 20)" },
    { "chain", OPT_CHAIN, '-', "Read a certificate chain" },
    { "no_cache", OPT_NO_CACHE, '-' },
    { "verify_return_error", OPT_VERIFY_RET_ERROR, '-' },
    { "status", OPT_STATUS, '-' },
    { "status_verbose", OPT_STATUS_VERBOSE, '-' },
    { "status_timeout", OPT_STATUS_TIMEOUT, 'n' },
    { "status_url", OPT_STATUS_URL, 's' },
#ifndef OPENSSL_NO_ENGINE
    { "engine", OPT_ENGINE, 's' },
#endif
    OPT_S_OPTIONS,
    OPT_V_OPTIONS,
    { NULL }
};

int s_server_main(int argc, char *argv[])
{
    X509_VERIFY_PARAM *vpm = NULL;
    STACK_OF(OPENSSL_STRING) *ssl_args = NULL;
    short port = PORT;
    char *CApath = NULL, *CAfile = NULL;
    uint8_t *context = NULL;
    char *dhfile = NULL, *prog;
    char *named_curve = NULL;
    int bugs = 0;
    int ret = 1;
    int off = 0;
    int no_tmp_rsa = 0, no_dhe = 0, no_ecdhe = 0, nocert = 0;
    int vpmtouched = 0, state = 0;
    const SSL_METHOD *meth = NULL;
    int socket_type = SOCK_STREAM;
    ENGINE *e = NULL;
    int s_cert_format = FORMAT_PEM, s_key_format = FORMAT_PEM;
    char *passarg = NULL, *pass = NULL;
    char *dpassarg = NULL, *dpass = NULL;
    int s_dcert_format = FORMAT_PEM, s_dkey_format = FORMAT_PEM;
    X509 *s_cert = NULL, *s_dcert = NULL;
    EVP_PKEY *s_key = NULL, *s_dkey = NULL;
    int no_cache = 0;
    EVP_PKEY *s_key2 = NULL;
    X509 *s_cert2 = NULL;
    tlsextctx tlsextcbp = { NULL, NULL, SSL_TLSEXT_ERR_ALERT_WARNING };
    const char *stnerr = NULL;
    OPTION_CHOICE o;
    const char *next_proto_neg_in = NULL;
    tlsextnextprotoctx next_proto = { NULL, 0 };
    const char *alpn_in = NULL;
    tlsextalpnctx alpn_ctx = { NULL, 0 };
    meth = SSLv23_server_method();

    local_argc = argc;
    local_argv = argv;

    s_server_init();
    vpm = X509_VERIFY_PARAM_new();
    if (vpm == NULL)
        goto end;

    prog = opt_init(argc, argv, s_server_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
            case OPT_EOF:
            case OPT_ERR:
            opthelp:
                BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
                goto end;
            case OPT_HELP:
                opt_help(s_server_options);
                ret = 0;
                goto end;

            case OPT_PORT:
                if (!extract_port(opt_arg(), &port))
                    goto end;
                break;
            case OPT_VERIFY:
                s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
                verify_depth = strtonum(opt_arg(), 0, INT_MAX, &stnerr);
                if (stnerr)
                    goto end;
                if (!s_quiet)
                    BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
                break;
            case OPT_UPPER_V_VERIFY:
                s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                                  SSL_VERIFY_CLIENT_ONCE;
                verify_depth = strtonum(opt_arg(), 0, INT_MAX, &stnerr);
                if (stnerr)
                    goto end;
                if (!s_quiet)
                    BIO_printf(bio_err, "verify depth is %d, must return a certificate\n",
                               verify_depth);
                break;
            case OPT_CONTEXT:
                context = (uint8_t *)opt_arg();
                break;
            case OPT_CERT:
                s_cert_file = opt_arg();
                break;
            case OPT_CERTFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &s_cert_format))
                    goto opthelp;
                break;
            case OPT_KEY:
                s_key_file = opt_arg();
                break;
            case OPT_KEYFORM:
                if (!opt_format(opt_arg(), OPT_FMT_ANY, &s_key_format))
                    goto opthelp;
                break;
            case OPT_PASS:
                passarg = opt_arg();
                break;
            case OPT_DHPARAM:
                dhfile = opt_arg();
                break;
            case OPT_DCERTFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &s_dcert_format))
                    goto opthelp;
                break;
            case OPT_DCERT:
                s_dcert_file = opt_arg();
                break;
            case OPT_DKEYFORM:
                if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &s_dkey_format))
                    goto opthelp;
                break;
            case OPT_DPASS:
                dpassarg = opt_arg();
                break;
            case OPT_DKEY:
                s_dkey_file = opt_arg();
                break;
            case OPT_NOCERT:
                nocert = 1;
                break;
            case OPT_CAPATH:
                CApath = opt_arg();
                break;
            case OPT_NO_CACHE:
                no_cache = 1;
                break;
            case OPT_S_CASES:
                if (ssl_args == NULL)
                    ssl_args = sk_OPENSSL_STRING_new_null();
                if (ssl_args == NULL || !sk_OPENSSL_STRING_push(ssl_args, opt_flag()) ||
                    !sk_OPENSSL_STRING_push(ssl_args, opt_arg())) {
                    BIO_printf(bio_err, "%s: Memory allocation failure\n", prog);
                    goto end;
                }
                break;
            case OPT_V_CASES:
                if (!opt_verify(o, vpm))
                    goto end;
                vpmtouched++;
                break;
            case OPT_VERIFY_RET_ERROR:
                verify_return_error = 1;
                break;
            case OPT_CAFILE:
                CAfile = opt_arg();
                break;
            case OPT_NBIO:
                s_nbio = 1;
                break;
            case OPT_DEBUG:
                s_debug = 1;
                break;
            case OPT_TLSEXTDEBUG:
                s_tlsextdebug = 1;
                break;
            case OPT_STATUS:
                s_tlsextstatus = 1;
                break;
            case OPT_STATUS_VERBOSE:
                s_tlsextstatus = tlscstatp.verbose = 1;
                break;
            case OPT_STATUS_TIMEOUT:
                s_tlsextstatus = 1;
                tlscstatp.timeout = strtonum(*(++argv), 0, INT_MAX, &stnerr);
                if (stnerr)
                    goto end;
                break;
            case OPT_STATUS_URL:
                s_tlsextstatus = 1;
                if (!OCSP_parse_url(opt_arg(), &tlscstatp.host, &tlscstatp.port,
                                    &tlscstatp.path, &tlscstatp.use_ssl)) {
                    BIO_printf(bio_err, "Error parsing URL\n");
                    goto end;
                }
                break;
            case OPT_MSG:
                s_msg = 1;
                break;
            case OPT_MSGFILE:
                bio_s_msg = BIO_new_file(opt_arg(), "w");
                break;
            case OPT_STATE:
                state = 1;
                break;
            case OPT_CRLF:
                s_crlf = 1;
                break;
            case OPT_QUIET:
                s_quiet = 1;
                break;
            case OPT_NO_TMP_RSA:
                no_tmp_rsa = 1;
                break;
            case OPT_NO_DHE:
                no_dhe = 1;
                break;
            case OPT_NO_ECDHE:
                no_ecdhe = 1;
                break;
            case OPT_WWW:
                www = 1;
                break;
            case OPT_UPPER_WWW:
                www = 2;
                break;
            case OPT_HTTP:
                www = 3;
                break;
            case OPT_TLS1_2:
                meth = TLSv1_2_server_method();
                break;
            case OPT_TLS1_1:
                meth = TLSv1_1_server_method();
                break;
            case OPT_TLS1:
                meth = TLSv1_server_method();
                break;
#ifndef OPENSSL_NO_DTLS1
            case OPT_DTLS1:
                meth = DTLSv1_server_method();
                socket_type = SOCK_DGRAM;
                break;
            case OPT_TIMEOUT:
                enable_timeouts = 1;
                break;
            case OPT_MTU:
                socket_mtu = strtonum(*(++argv), 0, LONG_MAX, &stnerr);
                if (stnerr)
                    goto end;
                break;
            case OPT_CHAIN:
                cert_chain = 1;
                break;
#endif
            case OPT_ID_PREFIX:
                session_id_prefix = opt_arg();
                break;
            case OPT_ENGINE:
                engine_id = opt_arg();
                break;
            case OPT_SERVERNAME:
                tlsextcbp.servername = opt_arg();
                break;
            case OPT_SERVERNAME_FATAL:
                tlsextcbp.extension_error = SSL_TLSEXT_ERR_ALERT_FATAL;
                break;
            case OPT_CERT2:
                s_cert_file2 = opt_arg();
                break;
            case OPT_KEY2:
                s_key_file2 = opt_arg();
                break;
            case OPT_NEXTPROTONEG:
                next_proto_neg_in = opt_arg();
                break;
            case OPT_ALPN:
                alpn_in = opt_arg();
                break;
            case OPT_KEYMATEXPORT:
                keymatexportlabel = opt_arg();
                break;
            case OPT_KEYMATEXPORTLEN:
                keymatexportlen = strtonum(*(++argv), 1, LONG_MAX, &stnerr);
                if (stnerr)
                    goto end;
                break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(engine_id, 1);
#endif

    if (!app_passwd(passarg, dpassarg, &pass, &dpass)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (s_key_file == NULL)
        s_key_file = s_cert_file;
    if (s_key_file2 == NULL)
        s_key_file2 = s_cert_file2;

    if (nocert == 0) {
        s_key = load_key(s_key_file, s_key_format, 0, pass, e,
                         "server certificate private key file");
        if (!s_key) {
            ERR_print_errors(bio_err);
            goto end;
        }

        s_cert = load_cert(s_cert_file, s_cert_format,
                           NULL, e, "server certificate file");

        if (!s_cert) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if (tlsextcbp.servername) {
            s_key2 = load_key(s_key_file2, s_key_format, 0, pass, e,
                              "second server certificate private key file");
            if (!s_key2) {
                ERR_print_errors(bio_err);
                goto end;
            }

            s_cert2 = load_cert(s_cert_file2, s_cert_format,
                                NULL, e, "second server certificate file");

            if (!s_cert2) {
                ERR_print_errors(bio_err);
                goto end;
            }
        }
    }

    if (next_proto_neg_in) {
        unsigned short len;
        next_proto.data = next_protos_parse(&len, next_proto_neg_in);
        if (next_proto.data == NULL)
            goto end;
        next_proto.len = len;
    } else {
        next_proto.data = NULL;
    }
    alpn_ctx.data = NULL;
    if (alpn_in) {
        unsigned short len;
        alpn_ctx.data = next_protos_parse(&len, alpn_in);
        if (alpn_ctx.data == NULL)
            goto end;
        alpn_ctx.len = len;
    }

    if (s_dcert_file) {

        if (s_dkey_file == NULL)
            s_dkey_file = s_dcert_file;

        s_dkey = load_key(s_dkey_file, s_dkey_format,
                          0, dpass, e,
                          "second certificate private key file");
        if (!s_dkey) {
            ERR_print_errors(bio_err);
            goto end;
        }

        s_dcert = load_cert(s_dcert_file, s_dcert_format,
                            NULL, e, "second server certificate file");

        if (!s_dcert) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (bio_s_out == NULL) {
        if (s_quiet && !s_debug && !s_msg) {
            bio_s_out = BIO_new(BIO_s_null());
        } else {
            if (bio_s_out == NULL)
                bio_s_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        }
    }

    if (nocert)
    {
        s_cert_file = NULL;
        s_key_file = NULL;
        s_dcert_file = NULL;
        s_dkey_file = NULL;
        s_cert_file2 = NULL;
        s_key_file2 = NULL;
    }

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (session_id_prefix) {
        if (strlen(session_id_prefix) >= 32)
            BIO_printf(bio_err,
                       "warning: id_prefix is too long, only one new session will be possible\n");
        else if (strlen(session_id_prefix) >= 16)
            BIO_printf(bio_err,
                       "warning: id_prefix is too long if you use SSLv2\n");
        if (!SSL_CTX_set_generate_session_id(ctx, generate_session_id)) {
            BIO_printf(bio_err, "error setting 'id_prefix'\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(bio_err, "id_prefix '%s' set.\n", session_id_prefix);
    }
    SSL_CTX_set_quiet_shutdown(ctx, 1);
    if (bugs)
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
    SSL_CTX_set_options(ctx, off);

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
    if (no_cache)
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    else
        SSL_CTX_sess_set_cache_size(ctx, 128);

    if ((!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) || (!SSL_CTX_set_default_verify_paths(ctx))) {
        /* BIO_printf(bio_err,"X509_load_verify_locations\n"); */
        ERR_print_errors(bio_err);
        /* goto end; */
    }
    if (vpm)
        SSL_CTX_set1_param(ctx, vpm);

    if (s_cert2) {
        ctx2 = SSL_CTX_new(meth);
        if (ctx2 == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (ctx2) {
        BIO_printf(bio_s_out, "Setting secondary ctx parameters\n");

        if (session_id_prefix) {
            if (strlen(session_id_prefix) >= 32)
                BIO_printf(bio_err,
                           "warning: id_prefix is too long, only one new session will be possible\n");
            else if (strlen(session_id_prefix) >= 16)
                BIO_printf(bio_err,
                           "warning: id_prefix is too long if you use SSLv2\n");
            if (!SSL_CTX_set_generate_session_id(ctx2, generate_session_id)) {
                BIO_printf(bio_err, "error setting 'id_prefix'\n");
                ERR_print_errors(bio_err);
                goto end;
            }
            BIO_printf(bio_err, "id_prefix '%s' set.\n", session_id_prefix);
        }
        SSL_CTX_set_quiet_shutdown(ctx2, 1);
        if (bugs)
            SSL_CTX_set_options(ctx2, SSL_OP_ALL);
        SSL_CTX_set_options(ctx2, off);

        if (state)
            SSL_CTX_set_info_callback(ctx2, apps_ssl_info_callback);

        if (no_cache)
            SSL_CTX_set_session_cache_mode(ctx2, SSL_SESS_CACHE_OFF);
        else
            SSL_CTX_sess_set_cache_size(ctx2, 128);

        if ((!SSL_CTX_load_verify_locations(ctx2, CAfile, CApath)) || (!SSL_CTX_set_default_verify_paths(ctx2))) {
            ERR_print_errors(bio_err);
        }
        if (vpm)
            SSL_CTX_set1_param(ctx2, vpm);
    }

    if (next_proto.data)
        SSL_CTX_set_next_protos_advertised_cb(ctx, next_proto_cb, &next_proto);
    if (alpn_ctx.data)
        SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, &alpn_ctx);

    if (!no_dhe) {
        DH *dh = NULL;

        if (dhfile)
            dh = load_dh_param(dhfile);
        else if (s_cert_file)
            dh = load_dh_param(s_cert_file);

        if (dh != NULL) {
            BIO_printf(bio_s_out, "Setting temp DH parameters\n");
        } else {
            BIO_printf(bio_s_out, "Using default temp DH parameters\n");
            dh = get_dh512();
        }
        (void)BIO_flush(bio_s_out);

        SSL_CTX_set_tmp_dh(ctx, dh);
        if (ctx2) {
            if (!dhfile) {
                DH *dh2 = load_dh_param(s_cert_file2);
                if (dh2 != NULL) {
                    BIO_printf(bio_s_out, "Setting temp DH parameters\n");
                    (void)BIO_flush(bio_s_out);

                    DH_free(dh);
                    dh = dh2;
                }
            }
            SSL_CTX_set_tmp_dh(ctx2, dh);
        }
        DH_free(dh);
    }

    if (!no_ecdhe) {
        EC_KEY *ecdh = NULL;

        if (named_curve) {
            int nid = OBJ_sn2nid(named_curve);

            if (nid == 0) {
                BIO_printf(bio_err, "unknown curve name (%s)\n",
                           named_curve);
                goto end;
            }
            ecdh = EC_KEY_new_by_curve_name(nid);
            if (ecdh == NULL) {
                BIO_printf(bio_err, "unable to create curve (%s)\n",
                           named_curve);
                goto end;
            }
        }

        if (ecdh != NULL) {
            BIO_printf(bio_s_out, "Setting temp ECDH parameters\n");
        } else {
            BIO_printf(bio_s_out, "Using default temp ECDH parameters\n");
            ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            if (ecdh == NULL) {
                BIO_printf(bio_err, "unable to create curve (nistp256)\n");
                goto end;
            }
        }
        (void)BIO_flush(bio_s_out);

        SSL_CTX_set_tmp_ecdh(ctx, ecdh);
        if (ctx2)
            SSL_CTX_set_tmp_ecdh(ctx2, ecdh);
        EC_KEY_free(ecdh);
    }

    if (!set_cert_key_stuff(ctx, s_cert, s_key))
        goto end;
    if (ctx2 && !set_cert_key_stuff(ctx2, s_cert2, s_key2))
        goto end;
    if (s_dcert != NULL) {
        if (!set_cert_key_stuff(ctx, s_dcert, s_dkey))
            goto end;
    }

    if (!no_tmp_rsa) {
        SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);
        if (ctx2)
            SSL_CTX_set_tmp_rsa_callback(ctx2, tmp_rsa_cb);
    }

    if (cipher != NULL) {
        if (!SSL_CTX_set_cipher_list(ctx, cipher)) {
            BIO_printf(bio_err, "error setting cipher list\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (ctx2 && !SSL_CTX_set_cipher_list(ctx2, cipher)) {
            BIO_printf(bio_err, "error setting cipher list\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);
    SSL_CTX_set_session_id_context(ctx, (void *)&s_server_session_id_context,
                                   sizeof s_server_session_id_context);

    /* Set DTLS cookie generation and verification callbacks */
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);

    if (ctx2) {
        SSL_CTX_set_verify(ctx2, s_server_verify, verify_callback);
        SSL_CTX_set_session_id_context(ctx2, (void *)&s_server_session_id_context,
                                       sizeof s_server_session_id_context);

        tlsextcbp.biodebug = bio_s_out;
        SSL_CTX_set_tlsext_servername_callback(ctx2, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx2, &tlsextcbp);
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }

    if (CAfile != NULL) {
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAfile));
        if (ctx2)
            SSL_CTX_set_client_CA_list(ctx2, SSL_load_client_CA_file(CAfile));
    }

    BIO_printf(bio_s_out, "ACCEPT\n");
    (void)BIO_flush(bio_s_out);
    if (www)
        do_server(port, socket_type, &accept_socket, www_body, context);
    else
        do_server(port, socket_type, &accept_socket, sv_body, context);
    print_stats(bio_s_out, ctx);
    ret = 0;
end:
    SSL_CTX_free(ctx);
    X509_free(s_cert);
    X509_free(s_dcert);
    EVP_PKEY_free(s_key);
    EVP_PKEY_free(s_dkey);
    free(pass);
    free(dpass);
    X509_VERIFY_PARAM_free(vpm);
    free(tlscstatp.host);
    free(tlscstatp.port);
    free(tlscstatp.path);
    SSL_CTX_free(ctx2);
    X509_free(s_cert2);
    EVP_PKEY_free(s_key2);
    free(next_proto.data);
    free(alpn_ctx.data);
    if (bio_s_out != NULL) {
        BIO_free(bio_s_out);
        bio_s_out = NULL;
    }
    return (ret);
}

static void print_stats(BIO *bio, SSL_CTX *ssl_ctx)
{
    BIO_printf(bio, "%4ld items in the session cache\n",
               SSL_CTX_sess_number(ssl_ctx));
    BIO_printf(bio, "%4ld client connects (SSL_connect())\n",
               SSL_CTX_sess_connect(ssl_ctx));
    BIO_printf(bio, "%4ld client renegotiates (SSL_connect())\n",
               SSL_CTX_sess_connect_renegotiate(ssl_ctx));
    BIO_printf(bio, "%4ld client connects that finished\n",
               SSL_CTX_sess_connect_good(ssl_ctx));
    BIO_printf(bio, "%4ld server accepts (SSL_accept())\n",
               SSL_CTX_sess_accept(ssl_ctx));
    BIO_printf(bio, "%4ld server renegotiates (SSL_accept())\n",
               SSL_CTX_sess_accept_renegotiate(ssl_ctx));
    BIO_printf(bio, "%4ld server accepts that finished\n",
               SSL_CTX_sess_accept_good(ssl_ctx));
    BIO_printf(bio, "%4ld session cache hits\n", SSL_CTX_sess_hits(ssl_ctx));
    BIO_printf(bio, "%4ld session cache misses\n", SSL_CTX_sess_misses(ssl_ctx));
    BIO_printf(bio, "%4ld session cache timeouts\n", SSL_CTX_sess_timeouts(ssl_ctx));
    BIO_printf(bio, "%4ld callback cache hits\n", SSL_CTX_sess_cb_hits(ssl_ctx));
    BIO_printf(bio, "%4ld cache full overflows (%ld allowed)\n",
               SSL_CTX_sess_cache_full(ssl_ctx),
               SSL_CTX_sess_get_cache_size(ssl_ctx));
}

static int sv_body(char *hostname, int s, uint8_t *context)
{
    char *buf = NULL;
    int ret = 1;
    int k, i;
    unsigned long l;
    SSL *con = NULL;
    BIO *sbio;
    struct timeval timeout;

    if ((buf = malloc(bufsize)) == NULL) {
        BIO_printf(bio_err, "out of memory\n");
        goto err;
    }

    if (s_nbio) {
        unsigned long sl = 1;

        if (!s_quiet)
            BIO_printf(bio_err, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &sl) < 0)
            ERR_print_errors(bio_err);
    }

    if (con == NULL) {
        con = SSL_new(ctx);
        if (s_tlsextdebug) {
            SSL_set_tlsext_debug_callback(con, tlsext_cb);
            SSL_set_tlsext_debug_arg(con, bio_s_out);
        }
        if (s_tlsextstatus) {
            SSL_CTX_set_tlsext_status_cb(ctx, cert_status_cb);
            tlscstatp.err = bio_err;
            SSL_CTX_set_tlsext_status_arg(ctx, &tlscstatp);
        }
        if (context)
            SSL_set_session_id_context(con, context,
                                       strlen((char *)context));
    }
    SSL_clear(con);

    if (SSL_version(con) == DTLS1_VERSION) {

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);

        if (enable_timeouts) {
            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_RCV_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_SND_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        }

        if (socket_mtu > 28) {
            SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
            SSL_set_mtu(con, socket_mtu - 28);
        } else
            /* want to do MTU discovery */
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

        /* turn on cookie exchange */
        SSL_set_options(con, SSL_OP_COOKIE_EXCHANGE);
    } else
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    SSL_set_bio(con, sbio, sbio);
    SSL_set_accept_state(con);
    /* SSL_set_fd(con,s); */

    if (s_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(con), (char *)bio_s_out);
    }
    if (s_msg) {
        SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_s_out);
    }
    if (s_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_s_out);
    }

    for (;;) {
        int read_from_terminal;
        int read_from_sslcon;
        struct pollfd pfd[2];
        int ptimeout;

        read_from_terminal = 0;
        read_from_sslcon = SSL_pending(con);

        if (!read_from_sslcon) {
            pfd[0].fd = fileno(stdin);
            pfd[0].events = POLLIN;
            pfd[1].fd = s;
            pfd[1].events = POLLIN;

            if ((SSL_version(con) == DTLS1_VERSION) && DTLSv1_get_timeout(con, &timeout))
                ptimeout = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
            else
                ptimeout = -1;

            i = poll(pfd, 2, ptimeout);

            if ((SSL_version(con) == DTLS1_VERSION) && DTLSv1_handle_timeout(con) > 0) {
                BIO_printf(bio_err, "TIMEOUT occurred\n");
            }

            if (i <= 0)
                continue;
            if (pfd[0].revents) {
                if ((pfd[0].revents & (POLLERR | POLLNVAL)))
                    continue;
                read_from_terminal = 1;
            }
            if (pfd[1].revents) {
                if ((pfd[1].revents & (POLLERR | POLLNVAL)))
                    continue;
                read_from_sslcon = 1;
            }
        }
        if (read_from_terminal) {
            if (s_crlf) {
                int j, lf_num;

                i = read(fileno(stdin), buf, bufsize / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (buf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    buf[j + lf_num] = buf[j];
                    if (buf[j] == '\n') {
                        lf_num--;
                        i++;
                        buf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = read(fileno(stdin), buf, bufsize);
            if (!s_quiet) {
                if ((i <= 0) || (buf[0] == 'Q')) {
                    BIO_printf(bio_s_out, "DONE\n");
                    shutdown((s), SHUT_RD);
                    close((s));
                    close_accept_socket();
                    ret = -11;
                    goto err;
                }
                if ((i <= 0) || (buf[0] == 'q')) {
                    BIO_printf(bio_s_out, "DONE\n");
                    if (SSL_version(con) != DTLS1_VERSION) {
                        shutdown((s), SHUT_RD);
                        close((s));
                    }
                    /*                close_accept_socket();
                    ret= -11;*/
                    goto err;
                }
                if ((buf[0] == 'r') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    SSL_renegotiate(con);
                    i = SSL_do_handshake(con);
                    printf("SSL_do_handshake -> %d\n", i);
                    i = 0; /*13; */
                    continue;
                    /* strcpy(buf,"server side RE-NEGOTIATE\n"); */
                }
                if ((buf[0] == 'R') && ((buf[1] == '\n') || (buf[1] == '\r'))) {
                    SSL_set_verify(con,
                                   SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
                    SSL_renegotiate(con);
                    i = SSL_do_handshake(con);
                    printf("SSL_do_handshake -> %d\n", i);
                    i = 0; /* 13; */
                    continue;
                    /* strcpy(buf,"server side RE-NEGOTIATE asking for client cert\n"); */
                }
                if (buf[0] == 'P') {
                    static const char *str = "Lets print some clear text\n";
                    BIO_write(SSL_get_wbio(con), str, strlen(str));
                }
                if (buf[0] == 'S') {
                    print_stats(bio_s_out, SSL_get_SSL_CTX(con));
                }
            }
            l = k = 0;
            for (;;) {
/* should do a select for the write */
#ifdef RENEG
                {
                    static count = 0;
                    if (++count == 100) {
                        count = 0;
                        SSL_renegotiate(con);
                    }
                }
#endif
                k = SSL_write(con, &(buf[l]), (unsigned int)i);
                switch (SSL_get_error(con, k)) {
                    case SSL_ERROR_NONE:
                        break;
                    case SSL_ERROR_WANT_WRITE:
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_X509_LOOKUP:
                        BIO_printf(bio_s_out, "Write BLOCK\n");
                        break;
                    case SSL_ERROR_SYSCALL:
                    case SSL_ERROR_SSL:
                        BIO_printf(bio_s_out, "ERROR\n");
                        ERR_print_errors(bio_err);
                        ret = 1;
                        goto err;
                    /* break; */
                    case SSL_ERROR_ZERO_RETURN:
                        BIO_printf(bio_s_out, "DONE\n");
                        ret = 1;
                        goto err;
                }
                if (k > 0) {
                    l += k;
                    i -= k;
                }
                if (i <= 0)
                    break;
            }
        }
        if (read_from_sslcon) {
            if (!SSL_is_init_finished(con)) {
                i = init_ssl_connection(con);

                if (i < 0) {
                    ret = 0;
                    goto err;
                } else if (i == 0) {
                    ret = 1;
                    goto err;
                }
            } else {
            again:
                i = SSL_read(con, (char *)buf, bufsize);
                switch (SSL_get_error(con, i)) {
                    case SSL_ERROR_NONE: {
                        int len, n;
                        for (len = 0; len < i;) {
                            do {
                                n = write(fileno(stdout), buf + len, i - len);
                            } while (n == -1 && errno == EINTR);

                            if (n < 0) {
                                BIO_printf(bio_s_out, "ERROR\n");
                                goto err;
                            }
                            len += n;
                        }
                    }
                        if (SSL_pending(con))
                            goto again;
                        break;
                    case SSL_ERROR_WANT_WRITE:
                    case SSL_ERROR_WANT_READ:
                        BIO_printf(bio_s_out, "Read BLOCK\n");
                        break;
                    case SSL_ERROR_SYSCALL:
                    case SSL_ERROR_SSL:
                        BIO_printf(bio_s_out, "ERROR\n");
                        ERR_print_errors(bio_err);
                        ret = 1;
                        goto err;
                    case SSL_ERROR_ZERO_RETURN:
                        BIO_printf(bio_s_out, "DONE\n");
                        ret = 1;
                        goto err;
                }
            }
        }
    }
err:
    if (con != NULL) {
        BIO_printf(bio_s_out, "shutting down SSL\n");
        SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        SSL_free(con);
    }
    BIO_printf(bio_s_out, "CONNECTION CLOSED\n");
    if (buf != NULL) {
        vigortls_zeroize(buf, bufsize);
        free(buf);
    }
    if (ret >= 0)
        BIO_printf(bio_s_out, "ACCEPT\n");
    (void)BIO_flush(bio_s_out);
    return (ret);
}

static void close_accept_socket(void)
{
    BIO_printf(bio_err, "shutdown accept socket\n");
    if (accept_socket >= 0) {
        shutdown((accept_socket), SHUT_RDWR);
        close((accept_socket));
    }
}

static int init_ssl_connection(SSL *con)
{
    int i;
    const char *str;
    X509 *peer;
    long verify_error;
    char buf[BUFSIZ];
    const uint8_t *next_proto_neg;
    unsigned next_proto_neg_len;
    uint8_t *exportedkeymat;

    i = SSL_accept(con);
    if (i <= 0) {
        if (BIO_sock_should_retry(i)) {
            BIO_printf(bio_s_out, "DELAY\n");
            return (1);
        }

        BIO_printf(bio_err, "ERROR\n");
        verify_error = SSL_get_verify_result(con);
        if (verify_error != X509_V_OK) {
            BIO_printf(bio_err, "verify error:%s\n",
                       X509_verify_cert_error_string(verify_error));
        } else
            ERR_print_errors(bio_err);
        return (0);
    }

    PEM_write_bio_SSL_SESSION(bio_s_out, SSL_get_session(con));

    peer = SSL_get_peer_certificate(con);
    if (peer != NULL) {
        BIO_printf(bio_s_out, "Client certificate\n");
        PEM_write_bio_X509(bio_s_out, peer);
        X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
        BIO_printf(bio_s_out, "subject=%s\n", buf);
        X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
        BIO_printf(bio_s_out, "issuer=%s\n", buf);
        X509_free(peer);
    }

    if (SSL_get_shared_ciphers(con, buf, sizeof buf) != NULL)
        BIO_printf(bio_s_out, "Shared ciphers:%s\n", buf);
    str = SSL_CIPHER_get_name(SSL_get_current_cipher(con));
    BIO_printf(bio_s_out, "CIPHER is %s\n", (str != NULL) ? str : "(NONE)");

    SSL_get0_next_proto_negotiated(con, &next_proto_neg, &next_proto_neg_len);
    if (next_proto_neg) {
        BIO_printf(bio_s_out, "NEXTPROTO is ");
        BIO_write(bio_s_out, next_proto_neg, next_proto_neg_len);
        BIO_printf(bio_s_out, "\n");
    }
#ifndef OPENSSL_NO_SRTP
    {
        SRTP_PROTECTION_PROFILE *srtp_profile
            = SSL_get_selected_srtp_profile(con);

        if (srtp_profile)
            BIO_printf(bio_s_out, "SRTP Extension negotiated, profile=%s\n",
                       srtp_profile->name);
    }
#endif
    if (SSL_cache_hit(con))
        BIO_printf(bio_s_out, "Reused session-id\n");
    BIO_printf(bio_s_out, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(con) ? "" : " NOT");
    if (keymatexportlabel != NULL) {
        BIO_printf(bio_s_out, "Keying material exporter:\n");
        BIO_printf(bio_s_out, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio_s_out, "    Length: %i bytes\n",
                   keymatexportlen);
        exportedkeymat = malloc(keymatexportlen);
        if (exportedkeymat != NULL) {
            if (!SSL_export_keying_material(con, exportedkeymat,
                                            keymatexportlen,
                                            keymatexportlabel,
                                            strlen(keymatexportlabel),
                                            NULL, 0, 0)) {
                BIO_printf(bio_s_out, "    Error\n");
            } else {
                BIO_printf(bio_s_out, "    Keying material: ");
                for (i = 0; i < keymatexportlen; i++)
                    BIO_printf(bio_s_out, "%02X",
                               exportedkeymat[i]);
                BIO_printf(bio_s_out, "\n");
            }
            free(exportedkeymat);
        }
    }

    return (1);
}

static DH *load_dh_param(const char *dhfile)
{
    DH *ret = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(dhfile, "r")) == NULL)
        goto err;
    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
err:
    if (bio != NULL)
        BIO_free(bio);
    return (ret);
}

static int www_body(char *hostname, int s, uint8_t *context)
{
    char *buf = NULL;
    int ret = 1;
    int i, j, k, dot;
    SSL *con;
    const SSL_CIPHER *c;
    BIO *io, *ssl_bio, *sbio;

    buf = malloc(bufsize);
    if (buf == NULL)
        return (0);
    io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    if ((io == NULL) || (ssl_bio == NULL))
        goto err;

    if (s_nbio) {
        unsigned long sl = 1;

        if (!s_quiet)
            BIO_printf(bio_err, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &sl) < 0)
            ERR_print_errors(bio_err);
    }

    /* lets make the output buffer a reasonable size */
    if (!BIO_set_write_buffer_size(io, bufsize))
        goto err;

    if ((con = SSL_new(ctx)) == NULL)
        goto err;
    if (s_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_s_out);
    }
    if (context)
        SSL_set_session_id_context(con, context,
                                   strlen((char *)context));

    sbio = BIO_new_socket(s, BIO_NOCLOSE);
    SSL_set_bio(con, sbio, sbio);
    SSL_set_accept_state(con);

    /* SSL_set_fd(con,s); */
    BIO_set_ssl(ssl_bio, con, BIO_CLOSE);
    BIO_push(io, ssl_bio);

    if (s_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
        BIO_set_callback_arg(SSL_get_rbio(con), (char *)bio_s_out);
    }
    if (s_msg) {
        SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_s_out);
    }

    for (;;) {
        i = BIO_gets(io, buf, bufsize - 1);
        if (i < 0) /* error */
        {
            if (!BIO_should_retry(io)) {
                if (!s_quiet)
                    ERR_print_errors(bio_err);
                goto err;
            } else {
                BIO_printf(bio_s_out, "read R BLOCK\n");
                sleep(1);
                continue;
            }
        } else if (i == 0) /* end of input */
        {
            ret = 1;
            goto end;
        }

        /* else we have data */
        if (((www == 1) && (strncmp("GET ", buf, 4) == 0)) ||
            ((www == 2) && (strncmp("GET /stats ", buf, 11) == 0))) {
            char *p;
            X509 *peer;
            STACK_OF(SSL_CIPHER) *sk;
            static const char *space = "                          ";

            BIO_puts(io, "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
            BIO_puts(io, "<HTML><BODY BGCOLOR=\"#ffffff\">\n");
            BIO_puts(io, "<pre>\n");
            BIO_puts(io, "\n");
            for (i = 0; i < local_argc; i++) {
                const char *myp;
                for (myp = local_argv[i]; *myp; myp++)
                    switch (*myp) {
                    case '<':
                        BIO_puts(io, "&lt;");
                        break;
                    case '>':
                        BIO_puts(io, "&gt;");
                        break;
                    case '&':
                        BIO_puts(io, "&amp;");
                        break;
                    default:
                        BIO_write(io, myp, 1);
                        break;
                    }
                BIO_write(io, " ", 1);
            }
            BIO_puts(io, "\n");

            BIO_printf(io,
                       "Secure Renegotiation IS%s supported\n",
                       SSL_get_secure_renegotiation_support(con) ?
                           "" :
                           " NOT");

            /* The following is evil and should not really
             * be done */
            BIO_printf(io, "Ciphers supported in s_server binary\n");
            sk = SSL_get_ciphers(con);
            j = sk_SSL_CIPHER_num(sk);
            for (i = 0; i < j; i++) {
                c = sk_SSL_CIPHER_value(sk, i);
                BIO_printf(io, "%-11s:%-25s",
                           SSL_CIPHER_get_version(c),
                           SSL_CIPHER_get_name(c));
                if ((((i + 1) % 2) == 0) && (i + 1 != j))
                    BIO_puts(io, "\n");
            }
            BIO_puts(io, "\n");
            p = SSL_get_shared_ciphers(con, buf, bufsize);
            if (p != NULL) {
                BIO_printf(io, "---\nCiphers common between both SSL end points:\n");
                j = i = 0;
                while (*p) {
                    if (*p == ':') {
                        BIO_write(io, space, 26 - j);
                        i++;
                        j = 0;
                        BIO_write(io, ((i % 3) ? " " : "\n"), 1);
                    } else {
                        BIO_write(io, p, 1);
                        j++;
                    }
                    p++;
                }
                BIO_puts(io, "\n");
            }
            BIO_printf(io, (SSL_cache_hit(con) ? "---\nReused, " : "---\nNew, "));
            c = SSL_get_current_cipher(con);
            BIO_printf(io, "%s, Cipher is %s\n",
                       SSL_CIPHER_get_version(c),
                       SSL_CIPHER_get_name(c));
            SSL_SESSION_print(io, SSL_get_session(con));
            BIO_printf(io, "---\n");
            print_stats(io, SSL_get_SSL_CTX(con));
            BIO_printf(io, "---\n");
            peer = SSL_get_peer_certificate(con);
            if (peer != NULL) {
                BIO_printf(io, "Client certificate\n");
                X509_print(io, peer);
                PEM_write_bio_X509(io, peer);
            } else
                BIO_puts(io, "no client certificate available\n");
            BIO_puts(io, "</BODY></HTML>\r\n\r\n");
            break;
        } else if ((www == 2 || www == 3)
                   && (strncmp("GET /", buf, 5) == 0)) {
            BIO *file;
            char *p, *e;
            static const char *text = "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";

            /* skip the '/' */
            p = &(buf[5]);

            dot = 1;
            for (e = p; *e != '\0'; e++) {
                if (e[0] == ' ')
                    break;

                switch (dot) {
                    case 1:
                        dot = (e[0] == '.') ? 2 : 0;
                        break;
                    case 2:
                        dot = (e[0] == '.') ? 3 : 0;
                        break;
                    case 3:
                        dot = (e[0] == '/') ? -1 : 0;
                        break;
                }
                if (dot == 0)
                    dot = (e[0] == '/') ? 1 : 0;
            }
            dot = (dot == 3) || (dot == -1); /* filename contains ".." component */

            if (*e == '\0') {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' is an invalid file name\r\n", p);
                break;
            }
            *e = '\0';

            if (dot) {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' contains '..' reference\r\n", p);
                break;
            }

            if (*p == '/') {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' is an invalid path\r\n", p);
                break;
            }

            /* if a directory, do the index thang */
            if (app_isdir(p) > 0) {
                BIO_puts(io, text);
                BIO_printf(io, "'%s' is a directory\r\n", p);
                break;
            }

            if ((file = BIO_new_file(p, "r")) == NULL) {
                BIO_puts(io, text);
                BIO_printf(io, "Error opening '%s'\r\n", p);
                ERR_print_errors(io);
                break;
            }

            if (!s_quiet)
                BIO_printf(bio_err, "FILE:%s\n", p);

            if (www == 2) {
                i = strlen(p);
                if (((i > 5) && (strcmp(&(p[i - 5]), ".html") == 0)) || ((i > 4) && (strcmp(&(p[i - 4]), ".php") == 0)) || ((i > 4) && (strcmp(&(p[i - 4]), ".htm") == 0)))
                    BIO_puts(io, "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
                else
                    BIO_puts(io, "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n");
            }
            /* send the file */
            for (;;) {
                i = BIO_read(file, buf, bufsize);
                if (i <= 0)
                    break;

#ifdef RENEG
                total_bytes += i;
                fprintf(stderr, "%d\n", i);
                if (total_bytes > 3 * 1024) {
                    total_bytes = 0;
                    fprintf(stderr, "RENEGOTIATE\n");
                    SSL_renegotiate(con);
                }
#endif

                for (j = 0; j < i;) {
#ifdef RENEG
                    {
                        static count = 0;
                        if (++count == 13) {
                            SSL_renegotiate(con);
                        }
                    }
#endif
                    k = BIO_write(io, &(buf[j]), i - j);
                    if (k <= 0) {
                        if (!BIO_should_retry(io))
                            goto write_error;
                        else {
                            BIO_printf(bio_s_out, "rwrite W BLOCK\n");
                        }
                    } else {
                        j += k;
                    }
                }
            }
        write_error:
            BIO_free(file);
            break;
        }
    }

    for (;;) {
        i = (int)BIO_flush(io);
        if (i <= 0) {
            if (!BIO_should_retry(io))
                break;
        } else
            break;
    }
end:
    /* make sure we re-use sessions */
    SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

err:

    if (ret >= 0)
        BIO_printf(bio_s_out, "ACCEPT\n");

    if (buf != NULL)
        free(buf);
    if (io != NULL)
        BIO_free_all(io);
    /*    if (ssl_bio != NULL) BIO_free(ssl_bio);*/
    return (ret);
}

static RSA *tmp_rsa_cb(SSL *s, int is_export, int keylength)
{
    BIGNUM *bn = NULL;
    static RSA *rsa_tmp = NULL;

    if (!rsa_tmp && ((bn = BN_new()) == NULL))
        BIO_printf(bio_err, "Allocation error in generating RSA key\n");
    if (!rsa_tmp && bn) {
        if (!s_quiet) {
            BIO_printf(bio_err, "Generating temp (%d bit) RSA key...", keylength);
            (void)BIO_flush(bio_err);
        }
        if (!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == NULL) || !RSA_generate_key_ex(rsa_tmp, keylength, bn, NULL)) {
            if (rsa_tmp)
                RSA_free(rsa_tmp);
            rsa_tmp = NULL;
        }
        if (!s_quiet) {
            BIO_printf(bio_err, "\n");
            (void)BIO_flush(bio_err);
        }
        BN_free(bn);
    }
    return (rsa_tmp);
}

#define MAX_SESSION_ID_ATTEMPTS 10
static int generate_session_id(const SSL *ssl, uint8_t *id,
                               unsigned int *id_len)
{
    unsigned int count = 0;
    do {
        if (RAND_bytes(id, *id_len) <= 0)
            return 0;
        /* Prefix the session_id with the required prefix. NB: If our
         * prefix is too long, clip it - but there will be worse effects
         * anyway, eg. the server could only possibly create 1 session
         * ID (ie. the prefix!) so all future session negotiations will
         * fail due to conflicts. */
        memcpy(id, session_id_prefix,
               (strlen(session_id_prefix) < *id_len) ?
                   strlen(session_id_prefix) :
                   *id_len);
    } while (SSL_has_matching_session_id(ssl, id, *id_len) && (++count < MAX_SESSION_ID_ATTEMPTS));
    if (count >= MAX_SESSION_ID_ATTEMPTS)
        return 0;
    return 1;
}
