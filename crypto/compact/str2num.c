/*
 * Copyright (c) 2014, Kurt Cancemi (kurt@x64architecture.com)
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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#define INVALID 1
#define OVERFLOW 2
#define UNDERFLOW 3
#define OUTOFRANGE 4

long long str2num(const char *nptr, long long minval, long long maxval, const int **stnerr)
{
    long long sl = 0;
    int error = 0;
    char *ex;

    errno = 0;
    if (minval > maxval) {
        error = INVALID;
    } else {
        sl = strtoll(nptr, &ex, 10);
        if (*ex != '\0') {
            error = INVALID;
        } else if ((sl == LLONG_MIN || sl == LLONG_MAX) && errno == ERANGE) {
            error = OUTOFRANGE;
        } else if (sl > maxval) {
            error = OVERFLOW;
        } else if (sl < minval) {
            error = UNDERFLOW;
        }
    }
    if (stnerr != NULL)
        *stnerr = &error;
    errno = error;
    if (error)
        return 0;

    return (sl);
}
