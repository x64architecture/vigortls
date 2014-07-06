/*
 * Copyright (c) 2014, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>


int CRYPTO_set_mem_functions(void *(*m)(size_t), void *(*r)(void *, size_t),
    void (*f)(void *))
{
    return 0;
}

int CRYPTO_set_mem_ex_functions(void *(*m)(size_t,const char *,int),
        void *(*r)(void *, size_t,const char *,int),
        void (*f)(void *))
{
    return 0;
}

int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*f)(void *))
{
    return 0;
}

int CRYPTO_set_locked_mem_ex_functions(
        void *(*m)(size_t,const char *,int),
        void (*f)(void *))
{
    return 0;
}

int CRYPTO_set_mem_debug_functions(void (*m)(void *,int,const char *,int,int),
            void (*r)(void *,void *,int,const char *,int,int),
            void (*f)(void *,int),
            void (*so)(long),
            long (*go)(void))
{
    return 0;
}


void CRYPTO_get_mem_functions(void *(**m)(size_t), void *(**r)(void *, size_t),
        void (**f)(void *))
{
    if (m != NULL)
        *m = malloc;
    if (r != NULL) 
        *r = realloc;
    if (f != NULL) 
        *f = free;
}

void *CRYPTO_malloc_locked(int num, const char *file, int line)
{

    if (num <= 0) 
        return NULL;

    return malloc(num);
}

void CRYPTO_free_locked(void *str)
{
    free(str);
}

void *CRYPTO_malloc(int num, const char *file, int line)
{
    if (num <= 0) 
        return NULL;

    return malloc(num);
}
char *CRYPTO_strdup(const char *str, const char *file, int line)
{
    return strdup(str);
}

void *CRYPTO_realloc(void *str, int num, const char *file, int line)
{

    if (num <= 0)
        return NULL;

    return realloc(str,num);
}

void *CRYPTO_realloc_clean(void *str, int old_len, int num, const char *file,
               int line)
{
    void *ret = NULL;

    if (num <= 0) 
        return NULL;

    if (num < old_len) 
        return NULL;

    ret = malloc(num);
    if (ret) {
        memcpy(ret, str, old_len);
        OPENSSL_cleanse(str, old_len);
        free(str);
    }

    return ret;
}

void CRYPTO_free(void *str)
{
    free(str);
}

void *CRYPTO_remalloc(void *a, int num, const char *file, int line)
{
    free(a);
    return malloc(num);
}

void CRYPTO_set_mem_debug_options(long bits)
{
    return;
}

long CRYPTO_get_mem_debug_options(void)
{
    return -1;
}