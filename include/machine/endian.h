#ifndef _HEADER_ENDIAN_H_
#define _HEADER_ENDIAN_H_

#ifdef _WIN32

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define PDP_ENDIAN 3412

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif

#elif defined __linux__
#include <endian.h>
#else
#include_next <machine/endian.h>
#endif

#endif
