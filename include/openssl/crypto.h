/* crypto/crypto.h */
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
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#ifndef HEADER_CRYPTO_H
#define HEADER_CRYPTO_H

#include <stdlib.h>

#include <openssl/opensslconf.h>
#include <stdio.h>

#include <openssl/stack.h>
#include <openssl/safestack.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backward compatibility to SSLeay */
/* This is more to be used to check the correct DLL is being used
 * in the MS world. */
#define SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER
#define SSLEAY_VERSION 0
/* #define SSLEAY_OPTIONS    1 no longer supported */
#define SSLEAY_CFLAGS 2
#define SSLEAY_BUILT_ON 3
#define SSLEAY_PLATFORM 4
#define SSLEAY_DIR 5

/* A generic structure to pass assorted data in a expandable way */
typedef struct openssl_item_st {
    int code;
    void *value;          /* Not used for flag attributes */
    size_t value_size;    /* Max size of value for output, length for input */
    size_t *value_length; /* Returned length of value for output */
} OPENSSL_ITEM;

/*
 * Old type for allocating dynamic locks. No longer used. Use the new thread
 * API instead.
 */
typedef struct {
    int dummy;
} CRYPTO_dynlock;

/* The following can be used to detect memory leaks in the SSLeay library.
 * It used, it turns on malloc checking */

#define CRYPTO_MEM_CHECK_OFF 0x0     /* an enume */
#define CRYPTO_MEM_CHECK_ON 0x1      /* a bit */
#define CRYPTO_MEM_CHECK_ENABLE 0x2  /* a bit */
#define CRYPTO_MEM_CHECK_DISABLE 0x3 /* an enume */

/* The following are bit values to turn on or off options connected to the
 * malloc checking functionality */

/* Adds time to the memory checking information */
#define V_CRYPTO_MDEBUG_TIME 0x1 /* a bit */
/* Adds thread number to the memory checking information */
#define V_CRYPTO_MDEBUG_THREAD 0x2 /* a bit */

#define V_CRYPTO_MDEBUG_ALL (V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD)

/* predec of the BIO type */
typedef struct bio_st BIO_dummy;

struct crypto_ex_data_st {
    STACK_OF(void)*sk;
};
DECLARE_STACK_OF(void)

/* Per class, we have a STACK of CRYPTO_EX_DATA_FUNCS for each CRYPTO_EX_DATA
 * entry.
 */

#define CRYPTO_EX_INDEX_BIO 0
#define CRYPTO_EX_INDEX_SSL 1
#define CRYPTO_EX_INDEX_SSL_CTX 2
#define CRYPTO_EX_INDEX_SSL_SESSION 3
#define CRYPTO_EX_INDEX_X509_STORE 4
#define CRYPTO_EX_INDEX_X509_STORE_CTX 5
#define CRYPTO_EX_INDEX_RSA 6
#define CRYPTO_EX_INDEX_DSA 7
#define CRYPTO_EX_INDEX_DH 8
#define CRYPTO_EX_INDEX_ENGINE 9
#define CRYPTO_EX_INDEX_X509 10
#define CRYPTO_EX_INDEX_UI 11
#define CRYPTO_EX_INDEX_ECDSA 12
#define CRYPTO_EX_INDEX_ECDH 13
#define CRYPTO_EX_INDEX_COMP 14
#define CRYPTO_EX_INDEX_STORE 15
#define CRYPTO_EX_INDEX_APP 16
#define CRYPTO_EX_INDEX__COUNT 17

/* This is the default callbacks, but we can have others as well:
 * this is needed in Win32 where the application malloc and the
 * library malloc may not be the same.
 */
#define CRYPTO_malloc_init() CRYPTO_set_mem_functions( \
    malloc, realloc, free)

#if defined CRYPTO_MDEBUG_ALL || defined CRYPTO_MDEBUG_TIME || defined CRYPTO_MDEBUG_THREAD
#ifndef CRYPTO_MDEBUG /* avoid duplicate #define */
#define CRYPTO_MDEBUG
#endif
#endif

/* Set standard debugging functions (not done by default
 * unless CRYPTO_MDEBUG is defined) */
#define CRYPTO_malloc_debug_init()                                                                                                              \
    do {                                                                                                                                        \
        CRYPTO_set_mem_debug_functions(CRYPTO_dbg_malloc, CRYPTO_dbg_realloc, CRYPTO_dbg_free, CRYPTO_dbg_set_options, CRYPTO_dbg_get_options); \
    } while (0)

int CRYPTO_mem_ctrl(int mode);
int CRYPTO_is_mem_check_on(void);

/* for applications */
#define MemCheck_start() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON)
#define MemCheck_stop() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF)

/* for library-internal use */
#define MemCheck_on() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
#define MemCheck_off() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
#define is_MemCheck_on() CRYPTO_is_mem_check_on()

#define OPENSSL_malloc(num) CRYPTO_malloc((int)num, __FILE__, __LINE__)
#define OPENSSL_strdup(str) CRYPTO_strdup((str), __FILE__, __LINE__)
#define OPENSSL_realloc(addr, num) \
    CRYPTO_realloc((char *)addr, (int)num, __FILE__, __LINE__)
#define OPENSSL_realloc_clean(addr, old_num, num) \
    CRYPTO_realloc_clean(addr, old_num, num, __FILE__, __LINE__)
#define OPENSSL_remalloc(addr, num) \
    CRYPTO_remalloc((char **)addr, (int)num, __FILE__, __LINE__)
#define OPENSSL_freeFunc CRYPTO_free
#define OPENSSL_free(addr) CRYPTO_free(addr)

#define OPENSSL_malloc_locked(num) \
    CRYPTO_malloc_locked((int)num, __FILE__, __LINE__)
#define OPENSSL_free_locked(addr) CRYPTO_free_locked(addr)

const char *SSLeay_version(int type);
unsigned long SSLeay(void);

int OPENSSL_issetugid(void);

/* Within a given class, get/register a new index */
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func);
/* Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a given
 * class (invokes whatever per-class callbacks are applicable) */
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       CRYPTO_EX_DATA *from);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
/* Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular index
 * (relative to the class type involved) */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);
/* This function cleans up all "ex_data" state. It mustn't be called under
 * potential race-conditions. */
void CRYPTO_cleanup_all_ex_data(void);

/*
 * These are the functions for the old threading API. These are all now no-ops
 * and should not be used.
 */
#define CRYPTO_get_new_lockid(name)    (0)
#define CRYPTO_num_locks()             (0)
/*
 * The old CRYPTO_lock() function has been removed completely without a
 * compatibility macro. This is because previously it could not return an error
 * response, but if any applications are using this they will not work and could
 * fail in strange ways. Better for them to fail at compile time.
 * 
 * void CRYPTO_lock(int mode, int type, const char *file, int line);
 */
#define CRYPTO_set_locking_callback(func)
#define CRYPTO_get_locking_callback()        (NULL)
#define CRYPTO_set_add_lock_callback(func)
#define CRYPTO_get_add_lock_callback()       (NULL)

/* This structure is no longer used */
typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;
#define CRYPTO_THREADID_set_numeric(id, val)
#define CRYPTO_THREADID_set_pointer(id, ptr)
#define CRYPTO_THREADID_set_callback(threadid_func)   (0)
#define CRYPTO_THREADID_get_callback()                (NULL)
#define CRYPTO_THREADID_current(id)
#define CRYPTO_THREADID_cmp(a, b)                     (-1)
#define CRYPTO_THREADID_cpy(dest, src)
#define CRYPTO_THREADID_hash(id)                      (0UL)

#define CRYPTO_set_id_callback(func)
#define CRYPTO_get_id_callback()                     (NULL)
#define CRYPTO_thread_id()                           (0UL)

#define CRYPTO_get_lock_name(type)                    (NULL)
#define CRYPTO_add_lock(pointer, amount, type, file, line) (0)

#define CRYPTO_get_new_dynlockid()                    (0)
#define CRYPTO_destroy_dynlockid(i)
#define CRYPTO_get_dynlock_value(i)                   (NULL)
#define CRYPTO_set_dynlock_create_callback(dyn_create_function)
#define CRYPTO_set_dynlock_lock_callback(dyn_lock_function)
#define CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function)
#define CRYPTO_get_dynlock_create_callback()          (NULL)
#define CRYPTO_get_dynlock_lock_callback()            (NULL)
#define CRYPTO_get_dynlock_destroy_callback()         (NULL)

/* CRYPTO_set_mem_functions includes CRYPTO_set_locked_mem_functions --
 * call the latter last if you need different functions */
int CRYPTO_set_mem_functions(void *(*m)(size_t), void *(*r)(void *, size_t), void (*f)(void *));
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
int CRYPTO_set_mem_ex_functions(void *(*m)(size_t, const char *, int),
                                void *(*r)(void *, size_t, const char *, int),
                                void (*f)(void *));
int CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t, const char *, int),
                                       void (*free_func)(void *));
int CRYPTO_set_mem_debug_functions(void (*m)(void *, int, const char *, int, int),
                                   void (*r)(void *, void *, int, const char *, int, int),
                                   void (*f)(void *, int),
                                   void (*so)(long),
                                   long (*go)(void));
void CRYPTO_get_mem_functions(void *(**m)(size_t), void *(**r)(void *, size_t), void (**f)(void *));
void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *));
void CRYPTO_get_mem_ex_functions(void *(**m)(size_t, const char *, int),
                                 void *(**r)(void *, size_t, const char *, int),
                                 void (**f)(void *));
void CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t, const char *, int),
                                        void (**f)(void *));
void CRYPTO_get_mem_debug_functions(void (**m)(void *, int, const char *, int, int),
                                    void (**r)(void *, void *, int, const char *, int, int),
                                    void (**f)(void *, int),
                                    void (**so)(long),
                                    long (**go)(void));

#ifndef VIGORTLS_INTERNAL
void *CRYPTO_malloc_locked(int num, const char *file, int line);
void CRYPTO_free_locked(void *ptr);
void *CRYPTO_malloc(int num, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
void CRYPTO_free(void *ptr);
void *CRYPTO_realloc(void *addr, int num, const char *file, int line);
#endif
void *CRYPTO_realloc_clean(void *addr, int old_num, int num, const char *file,
                           int line);
void *CRYPTO_remalloc(void *addr, int num, const char *file, int line);

void vigortls_zeroize(void *ptr, size_t len);
void OPENSSL_cleanse(void *ptr, size_t len);

void CRYPTO_set_mem_debug_options(long bits);
long CRYPTO_get_mem_debug_options(void);

#define CRYPTO_push_info(info) \
    CRYPTO_push_info_(info, __FILE__, __LINE__);
int CRYPTO_push_info_(const char *info, const char *file, int line);
int CRYPTO_pop_info(void);
int CRYPTO_remove_all_info(void);

/* Default debugging functions (enabled by CRYPTO_malloc_debug_init() macro;
 * used as default in CRYPTO_MDEBUG compilations): */
/* The last argument has the following significance:
 *
 * 0:    called before the actual memory allocation has taken place
 * 1:    called after the actual memory allocation has taken place
 */
void CRYPTO_dbg_malloc(void *addr, int num, const char *file, int line, int before_p);
void CRYPTO_dbg_realloc(void *addr1, void *addr2, int num, const char *file, int line, int before_p);
void CRYPTO_dbg_free(void *addr, int before_p);
/* Tell the debugging code about options.  By default, the following values
 * apply:
 *
 * 0:                           Clear all options.
 * V_CRYPTO_MDEBUG_TIME (1):    Set the "Show Time" option.
 * V_CRYPTO_MDEBUG_THREAD (2):  Set the "Show Thread Number" option.
 * V_CRYPTO_MDEBUG_ALL (3):     1 + 2
 */
void CRYPTO_dbg_set_options(long bits);
long CRYPTO_dbg_get_options(void);

void CRYPTO_mem_leaks_fp(FILE *);
void CRYPTO_mem_leaks(struct bio_st *bio);
/* unsigned long order, char *file, int line, int num_bytes, char *addr */
typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);

/* die if we have to */
void OpenSSLDie(const char *file, int line, const char *assertion);
#define OPENSSL_assert(e) (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e), 1))

/*
 * CRYPTO_memcmp returns zero if the |len| bytes at |in_a| and |in_b| are equal.
 * It takes an amount of time dependent on |len|, but independent of the contents
 * of |in_a| and |in_b|. Unlike memcmp, it cannot be used to put elements into a
 * defined order as the return value when in_a != in_b is undefined, other than
 * to be non-zero.
 */
int CRYPTO_memcmp(const volatile void * volatile in_a,
                  const volatile void * volatile in_b,
                  size_t len);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CRYPTO_strings(void);

/* Error codes for the CRYPTO functions. */

/* Function codes. */
# define CRYPTO_F_CRYPTO_DUP_EX_DATA                      110
# define CRYPTO_F_CRYPTO_FREE_EX_DATA                     111
# define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX                 100
# define CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID                103
# define CRYPTO_F_CRYPTO_GET_NEW_LOCKID                   101
# define CRYPTO_F_CRYPTO_NEW_EX_DATA                      112
# define CRYPTO_F_CRYPTO_SET_EX_DATA                      102
# define CRYPTO_F_DEF_ADD_INDEX                           104
# define CRYPTO_F_DEF_GET_CLASS                           105
# define CRYPTO_F_INT_DUP_EX_DATA                         106
# define CRYPTO_F_INT_FREE_EX_DATA                        107
# define CRYPTO_F_INT_NEW_EX_DATA                         108

/* Reason codes. */
# define CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK              100

#ifdef  __cplusplus
}
#endif
#endif
