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
/*
 * Based off of previous work by:
 * Dongsheng Song <dongsheng.song@gmail.com>
 */

#ifndef VIGORTLS_POLL_H
#define VIGORTLS_POLL_H

#if !defined(_WIN32)
#include_next <poll.h>
#else

#include <winsock2.h>

/* Type used for the number of file descriptors. */
typedef unsigned long int nfds_t;

/* Data structure describing a polling request. */
struct pollfd
{
    int fd;        /* file descriptor */
    short events;  /* requested events */
    short revents; /* returned events */
};

/* Event types that can be polled */
#define POLLIN 0x001  /* There is data to read. */
#define POLLPRI 0x002 /* There is urgent data to read. */
#define POLLOUT 0x004 /* Writing now will not block. */

#define POLLRDNORM 0x040 /* Normal data may be read. */
#define POLLRDBAND 0x080 /* Priority data may be read. */
#define POLLWRNORM 0x100 /* Writing now will not block. */
#define POLLWRBAND 0x200 /* Priority data may be written. */

/* Event types always implicitly polled. */
#define POLLERR 0x008    /* Error condition. */
#define POLLHUP 0x010    /* Hung up. */
#define POLLNVAL 0x020   /* Invalid polling request. */

#ifdef __cplusplus
extern "C" {
#endif

int poll(struct pollfd *pfds, nfds_t nfds, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_POLL */

#endif /* VIGORTLS_POLL_H */
