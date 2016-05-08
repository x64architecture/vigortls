#ifndef _HEADER_INTERNAL_THREADS_H
#define _HEADER_INTERNAL_THREADS_H

#include <openssl/threads.h>

#if defined(_WIN32)

#define _WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef INIT_ONCE CRYPTO_ONCE;

#define CRYPTO_ONCE_T_STATIC_INIT INIT_ONCE_STATIC_INIT

#else

#include <pthread.h>

typedef pthread_once_t CRYPTO_ONCE;
typedef pthread_key_t CRYPTO_THREAD_LOCAL;
typedef pthread_t CRYPTO_THREAD_ID;

#define CRYPTO_ONCE_T_STATIC_INIT PTHREAD_ONCE_INIT

#endif

CRYPTO_MUTEX *CRYPTO_thread_new(void);
void CRYPTO_thread_cleanup(CRYPTO_MUTEX *lock);

int CRYPTO_thread_read_lock(CRYPTO_MUTEX *lock);
int CRYPTO_thread_write_lock(CRYPTO_MUTEX *lock);
int CRYPTO_thread_unlock(CRYPTO_MUTEX *lock);

int CRYPTO_thread_run_once(CRYPTO_ONCE *once, void(*init)(void));

int CRYPTO_thread_init_local(CRYPTO_THREAD_LOCAL *key, void(*cleanup)(void *));
void *CRYPTO_thread_get_local(CRYPTO_THREAD_LOCAL *key);
int CRYPTO_thread_set_local(CRYPTO_THREAD_LOCAL *key, void *val);
int CRYPTO_thread_cleanup_local(CRYPTO_THREAD_LOCAL *key);

CRYPTO_THREAD_ID CRYPTO_thread_get_current_id(void);
int CRYPTO_thread_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);

int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_MUTEX *lock);

#endif
