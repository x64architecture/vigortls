#include_next <stdlib.h>

#ifndef _VIGORTLS_COMPAT_STDLIB_H_
#define _VIGORTLS_COMPAT_STDLIB_H_

void *reallocarray(void *ptr, size_t newmem, size_t size);
long long str2num(const char *nptr, long long minval, long long maxval, const int **stnerr);

#endif
