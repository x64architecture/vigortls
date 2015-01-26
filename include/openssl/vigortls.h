#ifndef _VIGORTLS_H_
#define _VIGORTLS_H_

#include <stddef.h>
#include <stdarg.h>

#ifndef HAVE_ASPRINTF
int asprintf(char **buf, const char *format, ...);
#endif

#ifndef HAVE_REALLOCARRAY
void *reallocarray(void *ptr, size_t newmem, size_t size);
#endif

#ifndef HAVE_SNPRINTF
int snprintf(char *buf, size_t n, const char *format, ...);
#endif

#ifndef HAVE_STRNDUP
char *strndup(const char *buf, size_t size);
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
