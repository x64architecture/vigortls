/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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

#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

static const SSL_METHOD *dtls1_get_client_method(int ver);
static int dtls1_get_hello_verify(SSL *s);

const SSL_METHOD DTLSv1_client_method_data = {
    .version = DTLS1_VERSION,
    .ssl_new = dtls1_new,
    .ssl_clear = dtls1_clear,
    .ssl_free = dtls1_free,
    .ssl_accept = ssl_undefined_function,
    .ssl_connect = dtls1_connect,
    .ssl_read = ssl3_read,
    .ssl_peek = ssl3_peek,
    .ssl_write = ssl3_write,
    .ssl_shutdown = dtls1_shutdown,
    .ssl_renegotiate = ssl3_renegotiate,
    .ssl_renegotiate_check = ssl3_renegotiate_check,
    .ssl_get_message = dtls1_get_message,
    .ssl_read_bytes = dtls1_read_bytes,
    .ssl_write_bytes = dtls1_write_app_data_bytes,
    .ssl_dispatch_alert = dtls1_dispatch_alert,
    .ssl_ctrl = dtls1_ctrl,
    .ssl_ctx_ctrl = ssl3_ctx_ctrl,
    .ssl_pending = ssl3_pending,
    .num_ciphers = ssl3_num_ciphers,
    .get_cipher = dtls1_get_cipher,
    .get_ssl_method = dtls1_get_client_method,
    .get_timeout = dtls1_default_timeout,
    .ssl3_enc = &DTLSv1_enc_data,
    .ssl_version = ssl_undefined_void_function,
    .ssl_callback_ctrl = ssl3_callback_ctrl,
    .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};

const SSL_METHOD *DTLSv1_client_method(void)
{
    return &DTLSv1_client_method_data;
}

static const SSL_METHOD *dtls1_get_client_method(int ver)
{
    if (ver == DTLS1_VERSION)
        return (DTLSv1_client_method());
    return (NULL);
}

int dtls1_connect(SSL *s)
{
    BUF_MEM *buf = NULL;
    void (*cb)(const SSL *ssl, int type, int val) = NULL;
    int ret = -1;
    int new_state, state, skip = 0;

    ERR_clear_error();
    errno = 0;

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);


    for (;;) {
        state = s->state;

        switch (s->state) {
            case SSL_ST_RENEGOTIATE:
                s->renegotiate = 1;
                s->state = SSL_ST_CONNECT;
                s->ctx->stats.sess_connect_renegotiate++;
            /* break */
            case SSL_ST_BEFORE:
            case SSL_ST_CONNECT:
            case SSL_ST_BEFORE | SSL_ST_CONNECT:
            case SSL_ST_OK | SSL_ST_CONNECT:

                s->server = 0;
                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_START, 1);

                if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
                    SSLerr(SSL_F_DTLS1_CONNECT, ERR_R_INTERNAL_ERROR);
                    ret = -1;
                    goto end;
                }

                /* s->version=SSL3_VERSION; */
                s->type = SSL_ST_CONNECT;

                if (s->init_buf == NULL) {
                    if ((buf = BUF_MEM_new()) == NULL) {
                        ret = -1;
                        goto end;
                    }
                    if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                        ret = -1;
                        goto end;
                    }
                    s->init_buf = buf;
                    buf = NULL;
                }

                if (!ssl3_setup_buffers(s)) {
                    ret = -1;
                    goto end;
                }

                /* setup buffing BIO */
                if (!ssl_init_wbio_buffer(s, 0)) {
                    ret = -1;
                    goto end;
                }

                /* don't push the buffering BIO quite yet */

                s->state = SSL3_ST_CW_CLNT_HELLO_A;
                s->ctx->stats.sess_connect++;
                s->init_num = 0;
                /* mark client_random uninitialized */
                memset(s->s3->client_random, 0, sizeof(s->s3->client_random));
                s->d1->send_cookie = 0;
                s->hit = 0;
                s->d1->change_cipher_spec_ok = 0;
                /* Should have been reset by ssl3_get_finished, too. */
                s->s3->change_cipher_spec = 0;
                break;


            case SSL3_ST_CW_CLNT_HELLO_A:
            case SSL3_ST_CW_CLNT_HELLO_B:

                s->shutdown = 0;

                /* every DTLS ClientHello resets Finished MAC */
                tls1_init_finished_mac(s);

                dtls1_start_timer(s);
                ret = ssl3_client_hello(s);
                if (ret <= 0)
                    goto end;

                if (s->d1->send_cookie) {
                    s->state = SSL3_ST_CW_FLUSH;
                    s->s3->tmp.next_state = SSL3_ST_CR_SRVR_HELLO_A;
                } else
                    s->state = SSL3_ST_CR_SRVR_HELLO_A;

                s->init_num = 0;

                    /* turn on buffering for the next lot of output */
                    if (s->bbio != s->wbio)
                        s->wbio = BIO_push(s->bbio, s->wbio);
                break;

            case SSL3_ST_CR_SRVR_HELLO_A:
            case SSL3_ST_CR_SRVR_HELLO_B:
                ret = ssl3_get_server_hello(s);
                if (ret <= 0)
                    goto end;
                else {
                    if (s->hit) {

                        s->state = SSL3_ST_CR_FINISHED_A;
                    } else
                        s->state = DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A;
                }
                s->init_num = 0;
                break;

            case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A:
            case DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B:

                ret = dtls1_get_hello_verify(s);
                if (ret <= 0)
                    goto end;
                dtls1_stop_timer(s);
                if (s->d1->send_cookie) /* start again, with a cookie */
                    s->state = SSL3_ST_CW_CLNT_HELLO_A;
                else
                    s->state = SSL3_ST_CR_CERT_A;
                s->init_num = 0;
                break;

            case SSL3_ST_CR_CERT_A:
            case SSL3_ST_CR_CERT_B:
                ret = ssl3_check_finished(s);
                if (ret <= 0)
                    goto end;
                if (ret == 2) {
                    s->hit = 1;
                    if (s->tlsext_ticket_expected)
                        s->state = SSL3_ST_CR_SESSION_TICKET_A;
                    else
                        s->state = SSL3_ST_CR_FINISHED_A;
                    s->init_num = 0;
                    break;
                }
                /* Check if it is anon DH. */
                if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)) {
                    ret = ssl3_get_server_certificate(s);
                    if (ret <= 0)
                        goto end;
                    if (s->tlsext_status_expected)
                        s->state = SSL3_ST_CR_CERT_STATUS_A;
                    else
                        s->state = SSL3_ST_CR_KEY_EXCH_A;
                } else {
                    skip = 1;
                    s->state = SSL3_ST_CR_KEY_EXCH_A;
                }
                s->init_num = 0;
                break;

            case SSL3_ST_CR_KEY_EXCH_A:
            case SSL3_ST_CR_KEY_EXCH_B:
                ret = ssl3_get_key_exchange(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_CR_CERT_REQ_A;
                s->init_num = 0;

                /* at this point we check that we have the
                 * required stuff from the server */
                if (!ssl3_check_cert_and_algorithm(s)) {
                    ret = -1;
                    goto end;
                }
                break;

            case SSL3_ST_CR_CERT_REQ_A:
            case SSL3_ST_CR_CERT_REQ_B:
                ret = ssl3_get_certificate_request(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_CR_SRVR_DONE_A;
                s->init_num = 0;
                break;

            case SSL3_ST_CR_SRVR_DONE_A:
            case SSL3_ST_CR_SRVR_DONE_B:
                ret = ssl3_get_server_done(s);
                if (ret <= 0)
                    goto end;
                dtls1_stop_timer(s);
                if (s->s3->tmp.cert_req)
                    s->s3->tmp.next_state = SSL3_ST_CW_CERT_A;
                else
                    s->s3->tmp.next_state = SSL3_ST_CW_KEY_EXCH_A;
                s->init_num = 0;

                    s->state = s->s3->tmp.next_state;
                break;

            case SSL3_ST_CW_CERT_A:
            case SSL3_ST_CW_CERT_B:
            case SSL3_ST_CW_CERT_C:
            case SSL3_ST_CW_CERT_D:
                dtls1_start_timer(s);
                ret = ssl3_send_client_certificate(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_CW_KEY_EXCH_A;
                s->init_num = 0;
                break;

            case SSL3_ST_CW_KEY_EXCH_A:
            case SSL3_ST_CW_KEY_EXCH_B:
                dtls1_start_timer(s);
                ret = ssl3_send_client_key_exchange(s);
                if (ret <= 0)
                    goto end;


                /* EAY EAY EAY need to check for DH fix cert
                 * sent back */
                /* For TLS, cert_req is set to 2, so a cert chain
                 * of nothing is sent, but no verify packet is sent */
                if (s->s3->tmp.cert_req == 1) {
                    s->state = SSL3_ST_CW_CERT_VRFY_A;
                } else {
                        s->state = SSL3_ST_CW_CHANGE_A;
                }

                s->init_num = 0;
                break;

            case SSL3_ST_CW_CERT_VRFY_A:
            case SSL3_ST_CW_CERT_VRFY_B:
                dtls1_start_timer(s);
                ret = ssl3_send_client_verify(s);
                if (ret <= 0)
                    goto end;
                    s->state = SSL3_ST_CW_CHANGE_A;
                s->init_num = 0;
                break;

            case SSL3_ST_CW_CHANGE_A:
            case SSL3_ST_CW_CHANGE_B:
                if (!s->hit)
                    dtls1_start_timer(s);
                ret = dtls1_send_change_cipher_spec(s, SSL3_ST_CW_CHANGE_A,
                                                    SSL3_ST_CW_CHANGE_B);
                if (ret <= 0)
                    goto end;

                s->state = SSL3_ST_CW_FINISHED_A;
                s->init_num = 0;

                s->session->cipher = s->s3->tmp.new_cipher;
                if (!s->method->ssl3_enc->setup_key_block(s)) {
                    ret = -1;
                    goto end;
                }

                if (!s->method->ssl3_enc->change_cipher_state(
                        s, SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
                    ret = -1;
                    goto end;
                }


                dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
                break;

            case SSL3_ST_CW_FINISHED_A:
            case SSL3_ST_CW_FINISHED_B:
                if (!s->hit)
                    dtls1_start_timer(s);
                ret = ssl3_send_finished(s, SSL3_ST_CW_FINISHED_A, SSL3_ST_CW_FINISHED_B,
                                         s->method->ssl3_enc->client_finished_label,
                                         s->method->ssl3_enc->client_finished_label_len);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_CW_FLUSH;

                /* clear flags */
                s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;
                if (s->hit) {
                    s->s3->tmp.next_state = SSL_ST_OK;
                    if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
                        s->state = SSL_ST_OK;
                        s->s3->flags |= SSL3_FLAGS_POP_BUFFER;
                        s->s3->delay_buf_pop_ret = 0;
                    }
                } else {

                    /* Allow NewSessionTicket if ticket expected */
                    if (s->tlsext_ticket_expected)
                        s->s3->tmp.next_state = SSL3_ST_CR_SESSION_TICKET_A;
                    else
                        s->s3->tmp.next_state = SSL3_ST_CR_FINISHED_A;
                }
                s->init_num = 0;
                break;

            case SSL3_ST_CR_SESSION_TICKET_A:
            case SSL3_ST_CR_SESSION_TICKET_B:
                ret = ssl3_get_new_session_ticket(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_CR_FINISHED_A;
                s->init_num = 0;
                break;

            case SSL3_ST_CR_CERT_STATUS_A:
            case SSL3_ST_CR_CERT_STATUS_B:
                ret = ssl3_get_cert_status(s);
                if (ret <= 0)
                    goto end;
                s->state = SSL3_ST_CR_KEY_EXCH_A;
                s->init_num = 0;
                break;

            case SSL3_ST_CR_FINISHED_A:
            case SSL3_ST_CR_FINISHED_B:
                s->d1->change_cipher_spec_ok = 1;
                ret = ssl3_get_finished(s, SSL3_ST_CR_FINISHED_A, SSL3_ST_CR_FINISHED_B);
                if (ret <= 0)
                    goto end;
                dtls1_stop_timer(s);

                if (s->hit)
                    s->state = SSL3_ST_CW_CHANGE_A;
                else
                    s->state = SSL_ST_OK;


                s->init_num = 0;
                break;

            case SSL3_ST_CW_FLUSH:
                s->rwstate = SSL_WRITING;
                if (BIO_flush(s->wbio) <= 0) {
                    /* If the write error was fatal, stop trying */
                    if (!BIO_should_retry(s->wbio)) {
                        s->rwstate = SSL_NOTHING;
                        s->state = s->s3->tmp.next_state;
                    }

                    ret = -1;
                    goto end;
                }
                s->rwstate = SSL_NOTHING;
                s->state = s->s3->tmp.next_state;
                break;

            case SSL_ST_OK:
                /* clean a few things up */
                ssl3_cleanup_key_block(s);

                /* If we are not 'joining' the last two packets,
                 * remove the buffering now */
                if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
                    ssl_free_wbio_buffer(s);
                /* else do it later in ssl3_write */

                s->init_num = 0;
                s->renegotiate = 0;
                s->new_session = 0;

                ssl_update_cache(s, SSL_SESS_CACHE_CLIENT);
                if (s->hit)
                    s->ctx->stats.sess_hit++;

                ret = 1;
                /* s->server=0; */
                s->handshake_func = dtls1_connect;
                s->ctx->stats.sess_connect_good++;

                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_DONE, 1);

                /* done with handshaking */
                s->d1->handshake_read_seq = 0;
                s->d1->next_handshake_write_seq = 0;
                goto end;
            /* break; */

            default:
                SSLerr(SSL_F_DTLS1_CONNECT, SSL_R_UNKNOWN_STATE);
                ret = -1;
                goto end;
                /* break; */
        }

        /* did we do anything */
        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_CONNECT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }
end:
    s->in_handshake--;


    BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s, SSL_CB_CONNECT_EXIT, ret);
    return (ret);
}

static int dtls1_get_hello_verify(SSL *s)
{
    int n, al, ok = 0;
    uint8_t *data;
    unsigned int cookie_len;

    n = s->method->ssl_get_message(s, DTLS1_ST_CR_HELLO_VERIFY_REQUEST_A,
                                   DTLS1_ST_CR_HELLO_VERIFY_REQUEST_B, -1,
                                   s->max_cert_list, &ok);

    if (!ok)
        return ((int)n);

    if (s->s3->tmp.message_type != DTLS1_MT_HELLO_VERIFY_REQUEST) {
        s->d1->send_cookie = 0;
        s->s3->tmp.reuse_message = 1;
        return (1);
    }

    if (2 > n)
        goto truncated;
    data = (uint8_t *)s->init_msg;

    if ((data[0] != (s->version >> 8)) || (data[1] != (s->version & 0xff))) {
        SSLerr(SSL_F_DTLS1_GET_HELLO_VERIFY, SSL_R_WRONG_SSL_VERSION);
        s->version = (s->version & 0xff00) | data[1];
        al = SSL_AD_PROTOCOL_VERSION;
        goto f_err;
    }
    data += 2;

    if (2 + 1 > n)
        goto truncated;
    cookie_len = *(data++);
    if (2 + 1 + cookie_len > n)
        goto truncated;
    if (cookie_len > sizeof(s->d1->cookie)) {
        al = SSL_AD_ILLEGAL_PARAMETER;
        goto f_err;
    }

    memcpy(s->d1->cookie, data, cookie_len);
    s->d1->cookie_len = cookie_len;

    s->d1->send_cookie = 1;
    return 1;

truncated:
    al = SSL_AD_DECODE_ERROR;
f_err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return -1;
}

int dtls1_send_client_verify(SSL *s)
{
    uint8_t *p, *d;
    uint8_t data[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
    EVP_PKEY *pkey;
    unsigned u = 0;
    unsigned long n;
    int j;

    if (s->state == SSL3_ST_CW_CERT_VRFY_A) {
        d = (uint8_t *)s->init_buf->data;
        p = &(d[DTLS1_HM_HEADER_LENGTH]);
        pkey = s->cert->key->privatekey;

        s->method->ssl3_enc->cert_verify_mac(s, NID_sha1,
                                             &(data[MD5_DIGEST_LENGTH]));

        if (pkey->type == EVP_PKEY_RSA) {
            s->method->ssl3_enc->cert_verify_mac(s, NID_md5, &(data[0]));
            if (RSA_sign(NID_md5_sha1, data, MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
                         &(p[2]), &u, pkey->pkey.rsa) <= 0) {
                SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY, ERR_R_RSA_LIB);
                goto err;
            }
            s2n(u, p);
            n = u + 2;
        } else if (pkey->type == EVP_PKEY_DSA) {
            if (!DSA_sign(pkey->save_type, &(data[MD5_DIGEST_LENGTH]),
                          SHA_DIGEST_LENGTH, &(p[2]), (unsigned int *)&j,
                          pkey->pkey.dsa)) {
                SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY, ERR_R_DSA_LIB);
                goto err;
            }
            s2n(j, p);
            n = j + 2;
        } else if (pkey->type == EVP_PKEY_EC) {
            if (!ECDSA_sign(pkey->save_type, &(data[MD5_DIGEST_LENGTH]),
                            SHA_DIGEST_LENGTH, &(p[2]), (unsigned int *)&j,
                            pkey->pkey.ec)) {
                SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY, ERR_R_ECDSA_LIB);
                goto err;
            }
            s2n(j, p);
            n = j + 2;
        } else {
            SSLerr(SSL_F_DTLS1_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        d = dtls1_set_message_header(s, d, SSL3_MT_CERTIFICATE_VERIFY, n, 0, n);

        s->init_num = (int)n + DTLS1_HM_HEADER_LENGTH;
        s->init_off = 0;

        /* buffer the message to handle re-xmits */
        dtls1_buffer_message(s, 0);

        s->state = SSL3_ST_CW_CERT_VRFY_B;
    }

    /* s->state = SSL3_ST_CW_CERT_VRFY_B */
    return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));
err:
    return (-1);
}
