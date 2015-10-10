/* apps/s_client.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/opensslconf.h>

#include "apps.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <stdcompat.h>
#include "s_apps.h"
#include "timeouts.h"

#define SSL_HOST_NAME "localhost"

#undef BUFSIZZ
#define BUFSIZZ 1024 * 8

extern int verify_depth;
extern int verify_error;
extern int verify_return_error;

static int c_nbio = 0;
static int c_Pause = 0;
static int c_debug = 0;
static int c_tlsextdebug = 0;
static int c_status_req = 0;
static int c_msg = 0;
static int c_showcerts = 0;

static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

static void print_stuff(BIO *berr, SSL *con, int full);
static int ocsp_resp_cb(SSL *s, void *arg);
static BIO *bio_c_out = NULL;
static BIO *bio_c_msg = NULL;
static int c_quiet = 0;
static int c_ign_eof = 0;

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    BIO *biodebug;
    int ack;
} tlsextctx;

static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *) arg;
    const char *hn = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (SSL_get_servername_type(s) != -1)
        p->ack = !SSL_session_reused(s) && hn != NULL;
    else
        BIO_printf(bio_err, "Can't use SSL_get_servername\n");

    return SSL_TLSEXT_ERR_OK;
}

/* This the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    uint8_t *data;
    unsigned short len;
    int status;
} tlsextnextprotoctx;

static tlsextnextprotoctx next_proto;

static int next_proto_cb(SSL *s, uint8_t **out, uint8_t *outlen, const uint8_t *in, unsigned int inlen, void *arg)
{
    tlsextnextprotoctx *ctx = arg;

    if (!c_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned i;
        BIO_printf(bio_c_out, "Protocols advertised by server: ");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_c_out, ", ", 2);
            BIO_write(bio_c_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_c_out, "\n", 1);
    }

    ctx->status = SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    return SSL_TLSEXT_ERR_OK;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_HOST,
    OPT_PORT,
    OPT_CONNECT,
    OPT_VERIFY,
    OPT_CERT,
    OPT_SESS_OUT,
    OPT_SESS_IN,
    OPT_CERTFORM,
    OPT_VERIFY_RET_ERROR,
    OPT_PREXIT,
    OPT_CRLF,
    OPT_QUIET,
    OPT_NBIO,
    OPT_SSL_CLIENT_ENGINE,
    OPT_IGN_EOF,
    OPT_NO_IGN_EOF,
    OPT_PAUSE,
    OPT_DEBUG,
    OPT_TLSEXTDEBUG,
    OPT_STATUS,
    OPT_MSG,
    OPT_MSGFILE,
    OPT_ENGINE,
    OPT_SHOWCERTS,
    OPT_NBIO_TEST,
    OPT_STATE,
    OPT_TLS1_2,
    OPT_TLS1_1,
    OPT_TLS1,
    OPT_DTLS1,
    OPT_TIMEOUT,
    OPT_MTU,
    OPT_KEYFORM,
    OPT_PASS,
    OPT_CAPATH,
    OPT_KEY,
    OPT_RECONNECT,
    OPT_CAFILE,
    OPT_NEXTPROTONEG,
    OPT_ALPN,
    OPT_STARTTLS,
    OPT_SERVERNAME,
    OPT_KEYMATEXPORT,
    OPT_KEYMATEXPORTLEN,
    OPT_FALLBACKSCSV,
} OPTION_CHOICE;

OPTIONS s_client_options[] = {
    { "help", OPT_HELP, '-', "Display this summary" },
    { "host", OPT_HOST, 's', "Use -connect instead" },
    { "port", OPT_PORT, 'p', "Use -connect instead" },
    { "connect", OPT_CONNECT, 's',
      "TCP/IP where to connect (default is " SSL_HOST_NAME ":" PORT_STR ")" },
    { "verify", OPT_VERIFY, 'p', "Turn on peer certificate verification" },
    { "cert", OPT_CERT, '<', "Certificate file to use, PEM format assumed" },
    { "certform", OPT_CERTFORM, 'F', "Certificate format (PEM or DER) PEM default" },
    { "key", OPT_KEY, '<', "Private key file to use, if not in -cert file" },
    { "keyform", OPT_KEYFORM, 'F', "Key format (PEM or DER) PEM default" },
    { "pass", OPT_PASS, 's', "Private key file pass phrase source" },
    { "CApath", OPT_CAPATH, '/', "PEM format directory of CA's" },
    { "CAfile", OPT_CAFILE, '<', "PEM format file of CA's" },
    { "reconnect", OPT_RECONNECT, '-',
      "Drop and re-make the connection with the same Session-ID" },
    { "pause", OPT_PAUSE, '-', "Sleep  after each read and write system call" },
    { "showcerts", OPT_SHOWCERTS, '-', "Show all certificates in the chain" },
    { "debug", OPT_DEBUG, '-', "Extra output" },
    { "msg", OPT_MSG, '-', "Show protocol messages" },
    { "msgfile", OPT_MSGFILE, '>' },
    { "nbio_test", OPT_NBIO_TEST, '-', "More ssl protocol testing" },
    { "state", OPT_STATE, '-', "Print the ssl states" },
    { "crlf", OPT_CRLF, '-', "Convert LF from terminal into CRLF" },
    { "quiet", OPT_QUIET, '-', "No s_client output" },
    { "ign_eof", OPT_IGN_EOF, '-', "Ignore input eof (default when -quiet)" },
    { "no_ign_eof", OPT_NO_IGN_EOF, '-', "Don't ignore input eof" },
    { "tls1_2", OPT_TLS1_2, '-', "Just use TLSv1.2" },
    { "tls1_1", OPT_TLS1_1, '-', "Just use TLSv1.1" },
    { "tls1", OPT_TLS1, '-', "Just use TLSv1" },
    { "dtls1", OPT_DTLS1, '-', "Just use DTLSv1" },
    { "timeout", OPT_TIMEOUT, '-' },
    { "mtu", OPT_MTU, 'p', "Set the link layer MTU" },
    { "starttls", OPT_STARTTLS, 's', "Use the STARTTLS command before starting TLS" },
    { "sess_out", OPT_SESS_OUT, '>', "File to write SSL session to" },
    { "sess_in", OPT_SESS_IN, '<', "File to read SSL session from" },
    { "keymatexport", OPT_KEYMATEXPORT, 's', "Export keying material using label" },
    { "keymatexportlen", OPT_KEYMATEXPORTLEN, 'p',
      "Export len bytes of keying material (default 20)" },
    { "fallback_scsv", OPT_FALLBACKSCSV, '-', "Send the fallback SCSV" },
    { "nbio", OPT_NBIO, '-', "Use non-blocking IO" },
    { "servername", OPT_SERVERNAME, 's', "Set TLS extension servername in ClientHello" },
    { "tlsextdebug", OPT_TLSEXTDEBUG, '-', "Hex dump of all TLS extensions received" },
    { "status", OPT_STATUS, '-', "Request certificate status from server" },
    { "alpn", OPT_ALPN, 's', "Enable ALPN extension, considering named protocols supported "
                             "(comma-separated list)" },
    { "nextprotoneg", OPT_NEXTPROTONEG, 's', "Enable NPN extension, considering named "
                                             "protocols supported (comma-separated list)" },
    { "verify_return_error", OPT_VERIFY_RET_ERROR, '-' },
    { "prexit", OPT_PREXIT, '-' },
#ifndef OPENSSL_NO_ENGINE
    { "engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device" },
    { "ssl_client_engine", OPT_SSL_CLIENT_ENGINE, 's' },
#endif
    { NULL }
};

typedef enum PROTOCOL_choice {
    PROTO_OFF,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP,
    PROTO_FTP,
    PROTO_TELNET,
    PROTO_XMPP
} PROTOCOL_CHOICE;

static OPT_PAIR services[] = {
    { "smtp", PROTO_SMTP },
    { "pop3", PROTO_POP3 },
    { "imap", PROTO_IMAP },
    { "ftp", PROTO_FTP },
    { "xmpp", PROTO_XMPP },
    { "telnet", PROTO_TELNET },
    { NULL }
};

int s_client_main(int argc, char **argv)
{
    unsigned int off = 0, clr = 0;
    SSL *con = NULL;
    int s, k, state = 0, af = AF_UNSPEC;
    char *prog;
    char *cbuf = NULL, *sbuf = NULL, *mbuf = NULL;
    int cbuf_len, cbuf_off;
    int sbuf_len, sbuf_off;
    char *port = PORT_STR;
    int full_log = 1;
    char *host = SSL_HOST_NAME;
    char *cert_file = NULL, *key_file = NULL;
    int cert_format = FORMAT_PEM, key_format = FORMAT_PEM;
    char *passarg = NULL, *pass = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    char *CApath = NULL, *CAfile = NULL, *cipher = NULL;
    int reconnect = 0, verify = SSL_VERIFY_NONE, bugs = 0;
    int crlf = 0;
    int write_tty, read_tty, write_ssl, read_ssl, tty_on, ssl_pending;
    SSL_CTX *ctx = NULL;
    int ret = 1, in_init = 1, i, nbio_test = 0;
    int starttls_proto = PROTO_OFF;
    int prexit = 0;
    X509_VERIFY_PARAM *vpm = NULL;
    const SSL_METHOD *meth = NULL;
    int socket_type = SOCK_STREAM;
    BIO *sbio;
    int mbuf_len = 0;
    struct timeval timeout;
    const char *stnerr = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine_id = NULL;
    char *ssl_client_engine_id = NULL;
    ENGINE *ssl_client_engine = NULL;
#endif
    ENGINE *e = NULL;
    char *servername = NULL;
    tlsextctx tlsextcbp = { NULL, 0 };
    const char *next_proto_neg_in = NULL;
    const char *alpn_in = NULL;
    char *sess_in = NULL;
    char *sess_out = NULL;
    struct sockaddr peer;
    int peerlen = sizeof(peer);
    int fallback_scsv = 0;
    int enable_timeouts = 0;
    long socket_mtu = 0;
    OPTION_CHOICE o;

    prog = opt_progname(argv[0]);
    meth = SSLv23_client_method();

    c_Pause = 0;
    c_quiet = 0;
    c_ign_eof = 0;
    c_debug = 0;
    c_msg = 0;
    c_showcerts = 0;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (((cbuf = malloc(BUFSIZZ)) == NULL) 
        || ((sbuf = malloc(BUFSIZZ)) == NULL) 
        || ((mbuf = malloc(BUFSIZZ)) == NULL)) {
        BIO_printf(bio_err, "out of memory\n");
        goto end;
    }

    verify_depth = 0;
    verify_error = X509_V_OK;
    c_nbio = 0;

    prog = opt_init(argc, argv, s_client_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(s_client_options);
            ret = 0;
            goto end;
        case OPT_HOST:
            host = opt_arg();
            break;
        case OPT_PORT:
            port = opt_arg();
            break;
        case OPT_CONNECT:
            if (!extract_host_port(opt_arg(), &host, NULL, &port))
                goto end;
            break;
        case OPT_VERIFY:
            verify = SSL_VERIFY_PEER;
            verify_depth = strtonum(opt_arg(), 0, INT_MAX, &stnerr);
            if (!c_quiet)
                BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
            break;
        case OPT_CERT:
            cert_file = opt_arg();
            break;
        case OPT_SESS_OUT:
            sess_out = opt_arg();
            break;
        case OPT_SESS_IN:
            sess_in = opt_arg();
            break;
        case OPT_CERTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &cert_format))
                goto opthelp;
            break;
        case OPT_VERIFY_RET_ERROR:
            verify_return_error = 1;
            break;
        case OPT_PREXIT:
            prexit = 1;
            break;
        case OPT_CRLF:
            crlf = 1;
            break;
        case OPT_QUIET:
            c_quiet = c_ign_eof = 1;
            break;
        case OPT_NBIO:
            c_nbio = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 1);
            break;
        case OPT_SSL_CLIENT_ENGINE:
#ifndef OPENSSL_NO_ENGINE
            ssl_client_engine = ENGINE_by_id(opt_arg());
            if (ssl_client_engine == NULL) {
                BIO_printf(bio_err, "Error getting client auth engine\n");
                goto opthelp;
            }
            break;
#endif
            break;
        case OPT_IGN_EOF:
            c_ign_eof = 1;
            break;
        case OPT_NO_IGN_EOF:
            c_ign_eof = 0;
            break;
        case OPT_PAUSE:
            c_Pause = 1;
            break;
        case OPT_DEBUG:
            c_debug = 1;
            break;
        case OPT_TLSEXTDEBUG:
            c_tlsextdebug = 1;
            break;
        case OPT_STATUS:
            c_status_req = 1;
            break;
        case OPT_MSG:
            c_msg = 1;
            break;
        case OPT_MSGFILE:
            bio_c_msg = BIO_new_file(opt_arg(), "w");
            break;
        case OPT_SHOWCERTS:
            c_showcerts = 1;
            break;
        case OPT_NBIO_TEST:
            nbio_test = 1;
            break;
        case OPT_STATE:
            state = 1;
            break;
        case OPT_TLS1_2:
            meth = TLSv1_2_client_method();
            break;
        case OPT_TLS1_1:
            meth = TLSv1_1_client_method();
            break;
        case OPT_TLS1:
            meth = TLSv1_client_method();
            break;
#ifndef OPENSSL_NO_DTLS1
        case OPT_DTLS1:
            meth = DTLSv1_client_method();
            socket_type = SOCK_DGRAM;
            break;
        case OPT_TIMEOUT:
            enable_timeouts = 1;
            break;
        case OPT_MTU:
            socket_mtu = strtonum(opt_arg(), 0, LONG_MAX, &stnerr);
            break;
#endif
        case OPT_FALLBACKSCSV:
            fallback_scsv = 1;
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &key_format))
                goto opthelp;
            break;
        case OPT_PASS:
            passarg = opt_arg();
            break;
        case OPT_KEY:
            key_file = opt_arg();
            break;
        case OPT_RECONNECT:
            reconnect = 5;
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NEXTPROTONEG:
            next_proto_neg_in = opt_arg();
            break;
        case OPT_ALPN:
            alpn_in = opt_arg();
            break;
        case OPT_STARTTLS:
            if (!opt_pair(opt_arg(), services, &starttls_proto))
                goto end;
            break;
        case OPT_SERVERNAME:
            servername = opt_arg();
            /* meth=TLSv1_client_method(); */
            break;
        case OPT_KEYMATEXPORT:
            keymatexportlabel = opt_arg();
            break;
        case OPT_KEYMATEXPORTLEN:
            keymatexportlen = strtonum(opt_arg(), 1, INT_MAX, &stnerr);
            break;
        }
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    next_proto.status = -1;
    if (next_proto_neg_in) {
        next_proto.data = next_protos_parse(&next_proto.len, next_proto_neg_in);
        if (next_proto.data == NULL) {
            BIO_printf(bio_err, "Error parsing -nextprotoneg argument\n");
            goto end;
        }
    } else
        next_proto.data = NULL;

#ifndef OPENSSL_NO_ENGINE
    e = setup_engine(engine_id, 1);
    if (ssl_client_engine_id) {
        ssl_client_engine = ENGINE_by_id(ssl_client_engine_id);
        if (!ssl_client_engine) {
            BIO_printf(bio_err,
                       "Error getting client auth engine\n");
            goto end;
        }
    }

#endif
    if (!app_passwd(passarg, NULL, &pass, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (key_file == NULL)
        key_file = cert_file;

    if (key_file)

    {

        key = load_key(key_file, key_format, 0, pass, e,
                       "client certificate private key file");
        if (!key) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (cert_file)

    {
        cert = load_cert(cert_file, cert_format,
                         NULL, e, "client certificate file");

        if (!cert) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (bio_c_out == NULL) {
        if (c_quiet && !c_debug && !c_msg) {
            bio_c_out = BIO_new(BIO_s_null());
        } else {
            if (bio_c_out == NULL)
                bio_c_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        }
    }

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (vpm)
        SSL_CTX_set1_param(ctx, vpm);

#ifndef OPENSSL_NO_ENGINE
    if (ssl_client_engine) {
        if (!SSL_CTX_set_client_cert_engine(ctx, ssl_client_engine)) {
            BIO_puts(bio_err, "Error setting client auth engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(ssl_client_engine);
            goto end;
        }
        ENGINE_free(ssl_client_engine);
    }
#endif

    if (bugs)
        SSL_CTX_set_options(ctx, SSL_OP_ALL | off);
    else
        SSL_CTX_set_options(ctx, off);

    if (clr)
        SSL_CTX_clear_options(ctx, clr);

    if (next_proto.data)
        SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &next_proto);

    if (alpn_in) {
        unsigned short alpn_len;
        uint8_t *alpn = next_protos_parse(&alpn_len, alpn_in);

        if (alpn == NULL) {
            BIO_printf(bio_err, "Error parsing -alpn argument\n");
            goto end;
        }
        SSL_CTX_set_alpn_protos(ctx, alpn, alpn_len);
        free(alpn);
    }

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
    if (cipher != NULL)
        if (!SSL_CTX_set_cipher_list(ctx, cipher)) {
            BIO_printf(bio_err, "error setting cipher list\n");
            ERR_print_errors(bio_err);
            goto end;
        }

    SSL_CTX_set_verify(ctx, verify, verify_callback);
    if (!set_cert_key_stuff(ctx, cert, key))
        goto end;

    if ((!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) || (!SSL_CTX_set_default_verify_paths(ctx))) {
        /* BIO_printf(bio_err,"error setting default verify locations\n"); */
        ERR_print_errors(bio_err);
        /* goto end; */
    }

    if (servername != NULL) {
        tlsextcbp.biodebug = bio_err;
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }

    con = SSL_new(ctx);
    if (sess_in) {
        SSL_SESSION *sess;
        BIO *stmp = BIO_new_file(sess_in, "r");
        if (!stmp) {
            BIO_printf(bio_err, "Can't open session file %s\n",
                       sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (!sess) {
            BIO_printf(bio_err, "Can't open session file %s\n",
                       sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        SSL_set_session(con, sess);
        SSL_SESSION_free(sess);
    }

    if (fallback_scsv)
        SSL_set_mode(con, SSL_MODE_SEND_FALLBACK_SCSV);
/*    SSL_set_cipher_list(con,"RC4-MD5"); */

re_start:

    if (init_client(&s, host, port, socket_type, af) == 0) {
        BIO_printf(bio_err, "connect:errno=%d\n", errno);
        shutdown((s), SHUT_RD);
        close((s));
        goto end;
    }
    BIO_printf(bio_c_out, "CONNECTED(%08X)\n", s);

    if (c_nbio) {
        unsigned long l = 1;
        BIO_printf(bio_c_out, "turning on non blocking io\n");
        if (BIO_socket_ioctl(s, FIONBIO, &l) < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (c_Pause & 0x01)
        SSL_set_debug(con, 1);

    if (SSL_version(con) == DTLS1_VERSION) {

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);
        if (getsockname(s, &peer, (void *)&peerlen) < 0) {
            BIO_printf(bio_err, "getsockname:errno=%d\n", errno);
            shutdown((s), SHUT_RD);
            close((s));
            goto end;
        }

        (void)BIO_ctrl_set_connected(sbio, 1, &peer);

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
    } else
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    if (nbio_test) {
        BIO *test;

        test = BIO_new(BIO_f_nbio_test());
        sbio = BIO_push(test, sbio);
    }

    if (c_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)bio_c_out);
    }
    if (c_msg) {
        SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_c_out);
    }
    if (c_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_c_out);
    }
    if (c_status_req) {
        SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, bio_c_out);
    }

    SSL_set_bio(con, sbio, sbio);
    SSL_set_connect_state(con);

    read_tty = 1;
    write_tty = 0;
    tty_on = 0;
    read_ssl = 1;
    write_ssl = 1;

    cbuf_len = 0;
    cbuf_off = 0;
    sbuf_len = 0;
    sbuf_off = 0;

    /* This is an ugly hack that does a lot of assumptions */
    /* We do have to handle multi-line responses which may come
        in a single packet or not. We therefore have to use
       BIO_gets() which does need a buffering BIO. So during
       the initial chitchat we do push a buffering BIO into the
       chain that is removed again later on to not disturb the
       rest of the s_client operation. */
    if (starttls_proto == PROTO_SMTP) {
        int foundit = 0;
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        /* wait for multi-line response to end from SMTP */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
        } while (mbuf_len > 3 && mbuf[3] == '-');
        /* STARTTLS command requires EHLO... */
        BIO_printf(fbio, "EHLO openssl.client.net\r\n");
        (void)BIO_flush(fbio);
        /* wait for multi-line response to end EHLO SMTP response */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (strstr(mbuf, "STARTTLS"))
                foundit = 1;
        } while (mbuf_len > 3 && mbuf[3] == '-');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        if (!foundit)
            BIO_printf(bio_err,
                       "didn't found starttls in server response,"
                       " try anyway...\n");
        BIO_printf(sbio, "STARTTLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_POP3) {
        BIO_read(sbio, mbuf, BUFSIZZ);
        BIO_printf(sbio, "STLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_IMAP) {
        int foundit = 0;
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        BIO_gets(fbio, mbuf, BUFSIZZ);
        /* STARTTLS command requires CAPABILITY... */
        BIO_printf(fbio, ". CAPABILITY\r\n");
        (void)BIO_flush(fbio);
        /* wait for multi-line CAPABILITY response */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (strstr(mbuf, "STARTTLS"))
                foundit = 1;
        } while (mbuf_len > 3 && mbuf[0] != '.');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        if (!foundit)
            BIO_printf(bio_err,
                       "didn't found STARTTLS in server response,"
                       " try anyway...\n");
        BIO_printf(sbio, ". STARTTLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_FTP) {
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        /* wait for multi-line response to end from FTP */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
        } while (mbuf_len > 3 && mbuf[3] == '-');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        BIO_printf(sbio, "AUTH TLS\r\n");
        BIO_read(sbio, sbuf, BUFSIZZ);
    }
    if (starttls_proto == PROTO_XMPP) {
        int seen = 0;
        BIO_printf(sbio, "<stream:stream "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         "xmlns='jabber:client' to='%s' version='1.0'>",
                   host);
        seen = BIO_read(sbio, mbuf, BUFSIZZ);
        mbuf[seen] = 0;
        while (!strstr(mbuf, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'")) {
            if (strstr(mbuf, "/stream:features>"))
                goto shut;
            seen = BIO_read(sbio, mbuf, BUFSIZZ);
            mbuf[seen] = 0;
        }
        BIO_printf(sbio, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        seen = BIO_read(sbio, sbuf, BUFSIZZ);
        sbuf[seen] = 0;
        if (!strstr(sbuf, "<proceed"))
            goto shut;
        mbuf[0] = 0;
    }

    for (;;) {
        struct pollfd pfd[3]; /* stdin, stdout, socket */
        int ptimeout = -1;

        if ((SSL_version(con) == DTLS1_VERSION) && DTLSv1_get_timeout(con, &timeout))
            ptimeout = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;

        if (SSL_in_init(con) && !SSL_total_renegotiations(con)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;
                if (sess_out) {
                    BIO *stmp = BIO_new_file(sess_out, "w");
                    if (stmp) {
                        PEM_write_bio_SSL_SESSION(stmp, SSL_get_session(con));
                        BIO_free(stmp);
                    } else
                        BIO_printf(bio_err, "Error writing session file %s\n", sess_out);
                }
                print_stuff(bio_c_out, con, full_log);
                if (full_log > 0)
                    full_log--;

                if (starttls_proto) {
                    BIO_printf(bio_err, "%s", mbuf);
                    /* We don't need to know any more */
                    starttls_proto = PROTO_OFF;
                }

                if (reconnect) {
                    reconnect--;
                    BIO_printf(bio_c_out, "drop connection and then reconnect\n");
                    SSL_shutdown(con);
                    SSL_set_connect_state(con);
                    shutdown((SSL_get_fd(con)), SHUT_RD);
                    close((SSL_get_fd(con)));
                    goto re_start;
                }
            }
        }

        ssl_pending = read_ssl && SSL_pending(con);

        pfd[0].fd = -1;
        pfd[1].fd = -1;
        if (!ssl_pending) {
            if (tty_on) {
                if (read_tty) {
                    pfd[0].fd = fileno(stdin);
                    pfd[0].events = POLLIN;
                }
                if (write_tty) {
                    pfd[1].fd = fileno(stdout);
                    pfd[1].events = POLLOUT;
                }
            }
            
            pfd[2].fd = SSL_get_fd(con);
            pfd[2].events = 0;
            
            if (read_ssl)
                pfd[2].events |= POLLIN;
            if (write_ssl)
                pfd[2].events |= POLLOUT;

            i = poll(pfd, 3, ptimeout);
            if (i < 0) {
                BIO_printf(bio_err, "bad poll %d\n", errno);
                goto shut;
                /* goto end; */
            }
        }

        if ((SSL_version(con) == DTLS1_VERSION) && DTLSv1_handle_timeout(con) > 0) {
            BIO_printf(bio_err, "TIMEOUT occurred\n");
        }

        if (!ssl_pending && (pfd[2].revents & (POLLOUT | POLLERR | POLLNVAL))) {
            if (pfd[2].revents & (POLLERR | POLLNVAL)) {
                BIO_printf(bio_err, "poll error");
                goto shut;
            }
            k = SSL_write(con, &(cbuf[cbuf_off]),
                          (unsigned int)cbuf_len);
            switch (SSL_get_error(con, k)) {
                case SSL_ERROR_NONE:
                    cbuf_off += k;
                    cbuf_len -= k;
                    if (k <= 0)
                        goto end;
                    /* we have done a  write(con,NULL,0); */
                    if (cbuf_len <= 0) {
                        read_tty = 1;
                        write_ssl = 0;
                    } else /* if (cbuf_len > 0) */
                    {
                        read_tty = 0;
                        write_ssl = 1;
                    }
                    break;
                case SSL_ERROR_WANT_WRITE:
                    BIO_printf(bio_c_out, "write W BLOCK\n");
                    write_ssl = 1;
                    read_tty = 0;
                    break;
                case SSL_ERROR_WANT_READ:
                    BIO_printf(bio_c_out, "write R BLOCK\n");
                    write_tty = 0;
                    read_ssl = 1;
                    write_ssl = 0;
                    break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                    BIO_printf(bio_c_out, "write X BLOCK\n");
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    if (cbuf_len != 0) {
                        BIO_printf(bio_c_out, "shutdown\n");
                        ret = 0;
                        goto shut;
                    } else {
                        read_tty = 1;
                        write_ssl = 0;
                        break;
                    }

                case SSL_ERROR_SYSCALL:
                    if ((k != 0) || (cbuf_len != 0)) {
                        BIO_printf(bio_err, "write:errno=%d\n", errno);
                        goto shut;
                    } else {
                        read_tty = 1;
                        write_ssl = 0;
                    }
                    break;
                case SSL_ERROR_SSL:
                    ERR_print_errors(bio_err);
                    goto shut;
            }
        } else if (!ssl_pending && (pfd[1].revents & (POLLOUT | POLLERR | POLLNVAL))) {
            if (pfd[1].revents & (POLLERR | POLLNVAL)) {
                BIO_printf(bio_err, "poll error");
                goto shut;
            }
            i = write(fileno(stdout), &(sbuf[sbuf_off]), sbuf_len);

            if (i <= 0) {
                BIO_printf(bio_c_out, "DONE\n");
                ret = 0;
                goto shut;
                /* goto end; */
            }

            sbuf_len -= i;
            ;
            sbuf_off += i;
            if (sbuf_len <= 0) {
                read_ssl = 1;
                write_tty = 0;
            }
        } else if (ssl_pending || (pfd[2].revents & (POLLIN | POLLHUP))) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(con);
                    iiii = 0;
                }
            }
#endif
            k = SSL_read(con, sbuf, 1024 /* BUFSIZZ */);

            switch (SSL_get_error(con, k)) {
                case SSL_ERROR_NONE:
                    if (k <= 0)
                        goto end;
                    sbuf_off = 0;
                    sbuf_len = k;

                    read_ssl = 0;
                    write_tty = 1;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    BIO_printf(bio_c_out, "read W BLOCK\n");
                    write_ssl = 1;
                    read_tty = 0;
                    break;
                case SSL_ERROR_WANT_READ:
                    BIO_printf(bio_c_out, "read R BLOCK\n");
                    write_tty = 0;
                    read_ssl = 1;
                    if ((read_tty == 0) && (write_ssl == 0))
                        write_ssl = 1;
                    break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                    BIO_printf(bio_c_out, "read X BLOCK\n");
                    break;
                case SSL_ERROR_SYSCALL:
                    ret = errno;
                    BIO_printf(bio_err, "read:errno=%d\n", ret);
                    goto shut;
                case SSL_ERROR_ZERO_RETURN:
                    BIO_printf(bio_c_out, "closed\n");
                    ret = 0;
                    goto shut;
                case SSL_ERROR_SSL:
                    ERR_print_errors(bio_err);
                    goto shut;
                    /* break; */
            }
        } else if (pfd[0].revents) {
            if (pfd[0].revents & (POLLERR | POLLNVAL)) {
                BIO_printf(bio_err, "poll error");
                goto shut;
            }
            if (crlf) {
                int j, lf_num;

                i = read(fileno(stdin), cbuf, BUFSIZZ / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (cbuf[j] == '\n')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    cbuf[j + lf_num] = cbuf[j];
                    if (cbuf[j] == '\n') {
                        lf_num--;
                        i++;
                        cbuf[j + lf_num] = '\r';
                    }
                }
                assert(lf_num == 0);
            } else
                i = read(fileno(stdin), cbuf, BUFSIZZ);

            if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == 'Q'))) {
                BIO_printf(bio_err, "DONE\n");
                ret = 0;
                goto shut;
            }

            if ((!c_ign_eof) && (cbuf[0] == 'R')) {
                BIO_printf(bio_err, "RENEGOTIATING\n");
                SSL_renegotiate(con);
                cbuf_len = 0;
            } else {
                cbuf_len = i;
                cbuf_off = 0;
            }

            write_ssl = 1;
            read_tty = 0;
        }
    }

    ret = 0;
shut:
    if (in_init)
        print_stuff(bio_c_out, con, full_log);
    SSL_shutdown(con);
    shutdown((SSL_get_fd(con)), SHUT_RD);
    close((SSL_get_fd(con)));
end:
    if (con != NULL) {
        if (prexit != 0)
            print_stuff(bio_c_out, con, 1);
        SSL_free(con);
    }
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (cert)
        X509_free(cert);
    if (key)
        EVP_PKEY_free(key);
    if (pass)
        free(pass);
    if (vpm)
        X509_VERIFY_PARAM_free(vpm);
    if (cbuf != NULL) {
        vigortls_zeroize(cbuf, BUFSIZZ);
        free(cbuf);
    }
    if (sbuf != NULL) {
        vigortls_zeroize(sbuf, BUFSIZZ);
        free(sbuf);
    }
    if (mbuf != NULL) {
        vigortls_zeroize(mbuf, BUFSIZZ);
        free(mbuf);
    }
    if (bio_c_out != NULL) {
        BIO_free(bio_c_out);
        bio_c_out = NULL;
    }
    return (ret);
}

static void print_stuff(BIO *bio, SSL *s, int full)
{
    X509 *peer = NULL;
    char *p;
    static const char *space = "                ";
    char buf[BUFSIZ];
    STACK_OF(X509) * sk;
    STACK_OF(X509_NAME) * sk2;
    const SSL_CIPHER *c;
    X509_NAME *xn;
    int j, i;
    uint8_t *exportedkeymat;

    if (full) {
        int got_a_chain = 0;

        sk = SSL_get_peer_cert_chain(s);
        if (sk != NULL) {
            got_a_chain = 1;

            BIO_printf(bio, "---\nCertificate chain\n");
            for (i = 0; i < sk_X509_num(sk); i++) {
                X509_NAME_oneline(X509_get_subject_name(
                                      sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "%2d s:%s\n", i, buf);
                X509_NAME_oneline(X509_get_issuer_name(
                                      sk_X509_value(sk, i)),
                                  buf, sizeof buf);
                BIO_printf(bio, "   i:%s\n", buf);
                if (c_showcerts)
                    PEM_write_bio_X509(bio, sk_X509_value(sk, i));
            }
        }

        BIO_printf(bio, "---\n");
        peer = SSL_get_peer_certificate(s);
        if (peer != NULL) {
            BIO_printf(bio, "Server certificate\n");
            if (!(c_showcerts && got_a_chain)) /* Redundant if we showed the whole chain */
                PEM_write_bio_X509(bio, peer);
            X509_NAME_oneline(X509_get_subject_name(peer),
                              buf, sizeof buf);
            BIO_printf(bio, "subject=%s\n", buf);
            X509_NAME_oneline(X509_get_issuer_name(peer),
                              buf, sizeof buf);
            BIO_printf(bio, "issuer=%s\n", buf);
        } else
            BIO_printf(bio, "no peer certificate available\n");

        sk2 = SSL_get_client_CA_list(s);
        if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0)) {
            BIO_printf(bio, "---\nAcceptable client certificate CA names\n");
            for (i = 0; i < sk_X509_NAME_num(sk2); i++) {
                xn = sk_X509_NAME_value(sk2, i);
                X509_NAME_oneline(xn, buf, sizeof(buf));
                BIO_write(bio, buf, strlen(buf));
                BIO_write(bio, "\n", 1);
            }
        } else {
            BIO_printf(bio, "---\nNo client certificate CA names sent\n");
        }
        p = SSL_get_shared_ciphers(s, buf, sizeof buf);
        if (p != NULL) {
            /* This works only for SSL 2.  In later protocol
             * versions, the client does not know what other
             * ciphers (in addition to the one to be used
             * in the current connection) the server supports. */

            BIO_printf(bio, "---\nCiphers common between both SSL endpoints:\n");
            j = i = 0;
            while (*p) {
                if (*p == ':') {
                    BIO_write(bio, space, 15 - j % 25);
                    i++;
                    j = 0;
                    BIO_write(bio, ((i % 3) ? " " : "\n"), 1);
                } else {
                    BIO_write(bio, p, 1);
                    j++;
                }
                p++;
            }
            BIO_write(bio, "\n", 1);
        }

        BIO_printf(bio, "---\nSSL handshake has read %ld bytes and written %ld bytes\n",
                   BIO_number_read(SSL_get_rbio(s)),
                   BIO_number_written(SSL_get_wbio(s)));
    }
    BIO_printf(bio, (SSL_cache_hit(s) ? "---\nReused, " : "---\nNew, "));
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "%s, Cipher is %s\n",
               SSL_CIPHER_get_version(c),
               SSL_CIPHER_get_name(c));
    if (peer != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get_pubkey(peer);
        BIO_printf(bio, "Server public key is %d bit\n",
                   EVP_PKEY_bits(pktmp));
        EVP_PKEY_free(pktmp);
    }
    BIO_printf(bio, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(s) ? "" : " NOT");

    {
        const uint8_t *proto;
        unsigned int proto_len;
        SSL_get0_alpn_selected(s, &proto, &proto_len);
        if (proto_len > 0) {
            BIO_printf(bio, "ALPN protocol: ");
            BIO_write(bio, proto, proto_len);
            BIO_write(bio, "\n", 1);
        } else
            BIO_printf(bio, "No ALPN negotiated\n");
    }

    SSL_SESSION_print(bio, SSL_get_session(s));
    if (keymatexportlabel != NULL) {
        BIO_printf(bio, "Keying material exporter:\n");
        BIO_printf(bio, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio, "    Length: %i bytes\n", keymatexportlen);
        exportedkeymat = malloc(keymatexportlen);
        if (exportedkeymat != NULL) {
            if (!SSL_export_keying_material(s, exportedkeymat,
                                            keymatexportlen,
                                            keymatexportlabel,
                                            strlen(keymatexportlabel),
                                            NULL, 0, 0)) {
                BIO_printf(bio, "    Error\n");
            } else {
                BIO_printf(bio, "    Keying material: ");
                for (i = 0; i < keymatexportlen; i++)
                    BIO_printf(bio, "%02X",
                               exportedkeymat[i]);
                BIO_printf(bio, "\n");
            }
            free(exportedkeymat);
        }
    }
    BIO_printf(bio, "---\n");
    if (peer != NULL)
        X509_free(peer);
    /* flush, or debugging output gets mixed with http response */
    (void)BIO_flush(bio);
}

static int ocsp_resp_cb(SSL *s, void *arg)
{
    const uint8_t *p;
    int len;
    OCSP_RESPONSE *rsp;
    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    BIO_puts(arg, "OCSP response: ");
    if (!p) {
        BIO_puts(arg, "no response sent\n");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        BIO_puts(arg, "response parse error\n");
        BIO_dump_indent(arg, (char *)p, len, 4);
        return 0;
    }
    BIO_puts(arg, "\n======================================\n");
    OCSP_RESPONSE_print(arg, rsp, 0);
    BIO_puts(arg, "======================================\n");
    OCSP_RESPONSE_free(rsp);
    return 1;
}
