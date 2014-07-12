/* crypto/o_str.h */
/* Kurt Cancemi places this file in the public domain. */

#ifndef HEADER_O_STR_H
#define HEADER_O_STR_H

/* for size_t */
#include <stddef.h>

int OPENSSL_strcasecmp(const char *str1, const char *str2);
int OPENSSL_strncasecmp(const char *str1, const char *str2, size_t n);

#endif
