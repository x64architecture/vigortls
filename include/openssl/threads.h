
#ifndef _HEADER_THREADS_H
#define _HEADER_THREADS_H

#if defined(_WIN32)
#include <stdint.h>

/* uint32_t aka DWORD */
typedef uint32_t CRYPTO_THREAD_LOCAL;
typedef uint32_t CRYPTO_THREAD_ID;

#else
#include <pthread.h>

typedef pthread_key_t CRYPTO_THREAD_LOCAL;
typedef pthread_t CRYPTO_THREAD_ID;

#endif

typedef void CRYPTO_MUTEX;

#endif
