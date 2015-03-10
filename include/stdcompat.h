/*
 * Copyright (c) 2015, Kurt Cancemi (kurt@x64architecture.com)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef VIGORTLS_STDCOMPAT_H
#define VIGORTLS_STDCOMPAT_H

#include <stddef.h>
#include <stdarg.h>

#ifndef HAVE_ASPRINTF
int asprintf(char **buf, const char *format, ...);
#endif

#ifndef HAVE_VASPRINTF
int vasprintf(char **buf, const char *format, va_list args);
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
