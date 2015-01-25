#ifndef _VIGORTLS_H_
#define _VIGORTLS_H_

#include <stddef.h>

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *ptr, size_t newmem, size_t size);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *nptr, long long minval, long long maxval, const char **stnerr);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dest, const char *src, size_t size);
#endif

#endif
