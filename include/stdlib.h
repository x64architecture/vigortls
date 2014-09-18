#include_next <stdlib.h>

#ifndef _VIGORTLS_COMPAT_STDLIB_H_
#define _VIGORTLS_COMPAT_STDLIB_H_

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *ptr, size_t newmem, size_t size);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *nptr, long long minval, long long maxval, const char **stnerr);
#endif

#endif
