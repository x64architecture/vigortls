/*
 * Public domain
 * unistd.h compatibility shim
 */

#ifndef _WIN32
#include_next <unistd.h>
#endif

#ifndef VIGORTLS_UNISTD_H
#define VIGORTLS_UNISTD_H

#ifndef HAVE_ISSETUGID
int issetugid(void);
#endif

#if defined _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define sleep(x) Sleep(1000 * x)
#endif

#endif
