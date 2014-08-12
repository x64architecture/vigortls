/* crypto/o_dir.c -*- mode:C; c-file-style: "eay" -*- */
/* Written by Richard Levitte (richard@levitte.org) for the OpenSSL
 * project 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include "directory.h"

/* The routines really come from the Levitte Programming, so to make
   life simple, let's just use the raw files and hack the symbols to
   fit our namespace.  */
#define LP_DIR_CTX OPENSSL_DIR_CTX
#define LP_dir_context_st OPENSSL_dir_context_st
#define LP_find_file OPENSSL_DIR_read
#define LP_find_file_end OPENSSL_DIR_end

/* The POSIXly macro for the maximum number of characters in a file path
   is NAME_MAX.  However, some operating systems use PATH_MAX instead.
   Therefore, it seems natural to first check for PATH_MAX and use that,
   and if it doesn't exist, use NAME_MAX. */
#if defined(PATH_MAX)
#define LP_ENTRY_SIZE PATH_MAX
#elif defined(NAME_MAX)
#define LP_ENTRY_SIZE NAME_MAX
#endif

/* Of course, there's the possibility that neither PATH_MAX nor NAME_MAX
   exist.  It's also possible that NAME_MAX exists but is define to a
   very small value (HP-UX offers 14), so we need to check if we got a
   result, and if it meets a minimum standard, and create or change it
   if not. */
#if !defined(LP_ENTRY_SIZE) || LP_ENTRY_SIZE < 255
#undef LP_ENTRY_SIZE
#define LP_ENTRY_SIZE 255
#endif

struct LP_dir_context_st {
    DIR *dir;
    char entry_name[LP_ENTRY_SIZE + 1];
};

const char *LP_find_file(LP_DIR_CTX **ctx, const char *directory)
{
    struct dirent *direntry = NULL;

    if (ctx == NULL || directory == NULL) {
        errno = EINVAL;
        return 0;
    }

    errno = 0;
    if (*ctx == NULL) {
        *ctx = (LP_DIR_CTX *)malloc(sizeof(LP_DIR_CTX));
        if (*ctx == NULL) {
            errno = ENOMEM;
            return 0;
        }
        memset(*ctx, '\0', sizeof(LP_DIR_CTX));

        (*ctx)->dir = opendir(directory);
        if ((*ctx)->dir == NULL) {
            int save_errno = errno; /* Probably not needed, but I'm paranoid */
            free(*ctx);
            *ctx = NULL;
            errno = save_errno;
            return 0;
        }
    }

    direntry = readdir((*ctx)->dir);
    if (direntry == NULL) {
        return 0;
    }

    strncpy((*ctx)->entry_name, direntry->d_name, sizeof((*ctx)->entry_name) - 1);
    (*ctx)->entry_name[sizeof((*ctx)->entry_name) - 1] = '\0';
    return (*ctx)->entry_name;
}

int LP_find_file_end(LP_DIR_CTX **ctx)
{
    if (ctx != NULL && *ctx != NULL) {
        int ret = closedir((*ctx)->dir);

        free(*ctx);
        switch (ret) {
            case 0:
                return 1;
            case -1:
                return 0;
            default:
                break;
        }
    }
    errno = EINVAL;
    return 0;
}
