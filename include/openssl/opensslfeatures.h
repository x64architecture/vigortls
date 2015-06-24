#define OPENSSL_NO_CMS
#define OPENSSL_NO_COMP
#define OPENSSL_NO_GMP
#define OPENSSL_NO_GOST
#define OPENSSL_NO_JPAKE
#define OPENSSL_NO_KRB5
#define OPENSSL_NO_MD2
#define OPENSSL_NO_MD4
#define OPENSSL_NO_MDC2
#define OPENSSL_NO_PSK
#define OPENSSL_NO_RC5
#define OPENSSL_NO_RFC3779
#define OPENSSL_NO_SCTP
#define OPENSSL_NO_SEED
#define OPENSSL_NO_SHA0
#define OPENSSL_NO_SRP
#define OPENSSL_NO_SSL2
#define OPENSSL_NO_STORE
#define OPENSSL_NO_BUF_FREELISTS
#define OPENSSL_NO_HEARTBEATS
#define OPENSSL_NO_DYNAMIC_ENGINE
#define OPENSSL_THREADS
#define OPENSSL_USE_IPV6

#if defined(__clang__) || defined(_MSC_VER) || defined(__GNUC__) && \
(__GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ < 1)) \
|| !defined(__x86_64) || !defined(__x86_64__)
 #define OPENSSL_NO_EC_NISTP_64_GCC_128
#endif

#ifndef OPENSSL_NO_ASM
 #define AES_ASM
 #define VPAES_ASM
 #define OPENSSL_BN_ASM_MONT
#if !defined(__arm__) && !defined(__arm)
 #define GHASH_ASM
 #define OPENSSL_IA32_SSE2
#endif
#if defined(__arm__) || defined(__arm)
 #define OPENSSL_BN_ASM_GF2m
#endif
#if defined(__x86_64) || defined(__x86_64__)
 #define OPENSSL_BN_ASM_MONT5
 #define OPENSSL_BN_ASM_GF2m
 #define BSAES_ASM
 #define ECP_NISTZ256_ASM
#endif
#endif
