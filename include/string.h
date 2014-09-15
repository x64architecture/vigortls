#include_next <string.h>

#ifndef _VIGORTLS_COMPAT_STRING_H_
#define _VIGORTLS_COMPAT_STRING_H_

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dest, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dest, const char *src, size_t size);
#endif

#endif
