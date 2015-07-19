#include <openssl/opensslfeatures.h>

#if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
# define VIGORTLS_64_BIT
# define VIGORTLS_X86_64
#elif defined(__x86) || defined(__i386) || defined(__i386__) || defined(_M_IX86)
# define VIGORTLS_32_BIT
# define VIGORTLS_X86
#elif defined(__arm) || defined(__arm__) || defined(_M_ARM)
# define VIGORTLS_32_BIT
# define VIGORTLS_ARM
#else
# error "Unknown target CPU"
#endif

#if defined(HEADER_CRYPTLIB_H) && !defined(OPENSSLDIR)
#define ENGINESDIR "/usr/lib/engines"
#define OPENSSLDIR "/etc/ssl"
#endif

#undef OPENSSL_UNISTD
#define OPENSSL_UNISTD <unistd.h>

#define OPENSSL_CPUID_OBJ

#undef BF_PTR

#define DES_RISC1
#define DES_UNROLL
