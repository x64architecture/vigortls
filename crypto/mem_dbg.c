/* Kurt Cancemi places this file in the public domain */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>

int CRYPTO_mem_ctrl(int mode)
{
    return (CRYPTO_MEM_CHECK_OFF);
}

int CRYPTO_is_mem_check_on(void)
{
    return (0);
}

void CRYPTO_dbg_set_options(long bits)
{
    return;
}

long CRYPTO_dbg_get_options(void)
{
    return (0);
}

int CRYPTO_push_info_(const char *info, const char *file, int line)
{
    return (0);
}

int CRYPTO_pop_info(void)
{
    return (0);
}

int CRYPTO_remove_all_info(void)
{
    return (0);
}

void CRYPTO_dbg_malloc(void *addr, int num, const char *file, int line,
                       int before_p)
{
    fprintf(stderr, "this is a bad idea");
    abort();
}

void CRYPTO_dbg_free(void *addr, int before_p)
{
    fprintf(stderr, "this is a bad idea");
    abort();
}

void CRYPTO_dbg_realloc(void *addr1, void *addr2, int num,
                        const char *file, int line, int before_p)
{
    fprintf(stderr, "this is a bad idea");
    abort();
}

void CRYPTO_mem_leaks(BIO *b)
{
    return;
}

void CRYPTO_mem_leaks_fp(FILE *fp)
{
    return;
}

typedef CRYPTO_MEM_LEAK_CB *PCRYPTO_MEM_LEAK_CB;

void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb)
{
    return;
}
