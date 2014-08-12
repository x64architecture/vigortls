#ifndef _HEADER_ENDIAN_H_
#define _HEADER_ENDIAN_H_

#ifdef __linux__
#include <endian.h>
#else
#include_next < machine / endian.h >
#endif

#endif
