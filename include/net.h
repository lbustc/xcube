/*
 * Copyright (c) 2006-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * tailored by xiaoyem
 */

#ifndef NET_INCLUDED
#define NET_INCLUDED

#include <sys/types.h>
#include <sys/stat.h>

#define NET_BLOCK    0
#define NET_NONBLOCK 1

/* FIXME: exported functions */
extern int net_tcp_server(const char *bindaddr, int port, char *err, size_t errlen);
extern int net_unix_server(const char *path, mode_t perm, char *err, size_t errlen);
extern int net_udp_server(const char *bindaddr, int port, char *err, size_t errlen);
extern int net_tcp_accept(int sock, char *ip, int *port, char *err, size_t errlen);
extern int net_unix_accept(int sock, char *err, size_t errlen);
extern int net_tcp_connect(const char *addr, int port, char *err, size_t errlen);
extern int net_tcp_nonblock_connect(const char *addr, int port, char *err, size_t errlen);
extern int net_unix_connect(const char *path, char *err, size_t errlen);
extern int net_unix_nonblock_connect(const char *path, char *err, size_t errlen);
extern int net_udp_connect(const char *addr, int port, char *err, size_t errlen);
extern int net_udp_nonblock_connect(const char *addr, int port, char *err, size_t errlen);
extern int net_read(int fd, char *buf, int count, int flags);
extern int net_write(int fd, const char *buf, int count, int flags);
extern int net_try_read(int fd, char *buf, int count, int maxtry, int flags);
extern int net_try_write(int fd, const char *buf, int count, int maxtry, int flags);
extern int net_nonblock(int fd, char *err, size_t errlen);
extern int net_tcp_nodelay(int fd, char *err, size_t errlen);
extern int net_tcp_keepalive(int fd, char *err, size_t errlen);

#endif /* NET_INCLUDED */

