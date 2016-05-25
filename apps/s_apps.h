/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <sys/types.h>
#include <openssl/opensslconf.h>

#define PORT 4433
#define PORT_STR "4433"
#define PROTOCOL "tcp"

int do_server(int port, int type, int *ret, int (*cb)(char *hostname, int s, uint8_t *context), uint8_t *context);
#ifdef HEADER_X509_H
int verify_callback(int ok, X509_STORE_CTX *ctx);
#endif
#ifdef HEADER_SSL_H
int set_cert_stuff(SSL_CTX *ctx, char *cert_file, char *key_file);
int set_cert_key_stuff(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key);
int set_cert_key_and_authz(SSL_CTX *ctx, X509 *cert, EVP_PKEY *key,
                           uint8_t *authz, size_t authz_length);
int ssl_print_sigalgs(BIO *out, SSL *s);
int ssl_print_curves(BIO *out, SSL *s);
#endif
int init_client(int *sock, char *server, char *port, int type, int af);
int should_retry(int i);
int extract_port(char *str, short *port_ptr);
int extract_host_port(char *str, char **host_ptr, uint8_t *ip, char **p);

long bio_dump_callback(BIO *bio, int cmd, const char *argp,
                       int argi, long argl, long ret);

#ifdef HEADER_SSL_H
void apps_ssl_info_callback(const SSL *s, int where, int ret);
void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
void tlsext_cb(SSL *s, int client_server, int type,
               uint8_t *data, int len,
               void *arg);
#endif

int generate_cookie_callback(SSL *ssl, uint8_t *cookie, unsigned int *cookie_len);
int verify_cookie_callback(SSL *ssl, uint8_t *cookie, unsigned int cookie_len);
