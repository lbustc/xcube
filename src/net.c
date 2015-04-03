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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "net.h"

static void net_set_error(char *err, size_t errlen, const char *fmt, ...) {
	va_list ap;

	if (err == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static int net_create_socket(int domain, char *err, size_t errlen) {
	int sock, on = 1;

	if ((sock = socket(domain, SOCK_STREAM, 0)) == -1) {
		net_set_error(err, errlen, "creating socket: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) == -1) {
		net_set_error(err, errlen, "setsockopt SO_REUSEADDR: %s", strerror(errno));
		return -1;
	}
	return sock;
}

static int net_listen(int sock, struct sockaddr *sa, socklen_t len, char *err, size_t errlen) {
	if (bind(sock, sa, len) == -1) {
		net_set_error(err, errlen, "bind: %s", strerror(errno));
		close(sock);
		return -1;
	}
	/* use a backlog of 512 entries */
	if (listen(sock, 511) == -1) {
		net_set_error(err, errlen, "listen: %s", strerror(errno));
		close(sock);
		return -1;
	}
	return 0;
}

static int net_generic_accept(int sock, struct sockaddr *sa, socklen_t *len, char *err, size_t errlen) {
	int fd;

	for (;;) {
		if ((fd = accept(sock, sa, len)) == -1) {
			if (errno == EINTR)
				continue;
			else {
				net_set_error(err, errlen, "accept: %s", strerror(errno));
				return -1;
			}
		}
		break;
	}
	return fd;
}

static int net_tcp_generic_connect(const char *addr, int port, int flags, char *err, size_t errlen) {
	int sock;
	struct sockaddr_in sa;

	if ((sock = net_create_socket(AF_INET, err, errlen)) == -1)
		return -1;
	sa.sin_family = AF_INET;
	sa.sin_port   = htons(port);
	if (inet_aton(addr, &sa.sin_addr) == 0) {
		struct hostent *he;

		if ((he = gethostbyname(addr)) == NULL) {
			net_set_error(err, errlen, "can't resolve: %s", addr);
			close(sock);
			return -1;
		}
		memcpy(&sa.sin_addr, he->h_addr, sizeof (struct in_addr));
	}
	if (flags & NET_NONBLOCK && net_nonblock(sock, err, errlen) != 0)
		return -1;
	if (connect(sock, (struct sockaddr *)&sa, sizeof sa) == -1) {
		if (errno == EINPROGRESS && flags & NET_NONBLOCK)
			return sock;
		net_set_error(err, errlen, "connect: %s", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

static int net_unix_generic_connect(const char *path, int flags, char *err, size_t errlen) {
	int sock;
	struct sockaddr_un sa;

	if ((sock = net_create_socket(AF_LOCAL, err, errlen)) == -1)
		return -1;
	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
	if (flags & NET_NONBLOCK && net_nonblock(sock, err, errlen) != 0)
		return -1;
	if (connect(sock, (struct sockaddr *)&sa, sizeof sa) == -1) {
		if (errno == EINPROGRESS && flags & NET_NONBLOCK)
			return sock;
		net_set_error(err, errlen, "connect: %s", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

static int net_udp_generic_connect(const char *addr, int port, int flags, char *err, size_t errlen) {
	int sock;
	struct sockaddr_in sa;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		net_set_error(err, errlen, "creating socket: %s", strerror(errno));
		return -1;
	}
	sa.sin_family = AF_INET;
	sa.sin_port   = htons(port);
	if (inet_aton(addr, &sa.sin_addr) == 0) {
		struct hostent *he;

		if ((he = gethostbyname(addr)) == NULL) {
			net_set_error(err, errlen, "can't resolve: %s", addr);
			close(sock);
			return -1;
		}
		memcpy(&sa.sin_addr, he->h_addr, sizeof (struct in_addr));
	}
	if (flags & NET_NONBLOCK && net_nonblock(sock, err, errlen) != 0)
		return -1;
	if (connect(sock, (struct sockaddr *)&sa, sizeof sa) == -1) {
		if (errno == EINPROGRESS && flags & NET_NONBLOCK)
			return sock;
		net_set_error(err, errlen, "connect: %s", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

int net_tcp_server(const char *bindaddr, int port, char *err, size_t errlen) {
	int sock;
	struct sockaddr_in sa;

	if ((sock = net_create_socket(AF_INET, err, errlen)) == -1)
		return -1;
	memset(&sa, '\0', sizeof sa);
	sa.sin_family      = AF_INET;
	sa.sin_port        = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bindaddr && inet_aton(bindaddr, &sa.sin_addr) == 0) {
		net_set_error(err, errlen, "invalid bind address");
		close(sock);
		return -1;
	}
	if (net_listen(sock, (struct sockaddr *)&sa, sizeof sa, err, errlen) == -1)
		return -1;
	return sock;
}

int net_unix_server(const char *path, mode_t perm, char *err, size_t errlen) {
	int sock;
	struct sockaddr_un sa;

	if ((sock = net_create_socket(AF_LOCAL, err, errlen)) == -1)
		return -1;
	memset(&sa, '\0', sizeof sa);
	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
	if (net_listen(sock, (struct sockaddr *)&sa, sizeof sa, err, errlen) == -1)
		return -1;
	if (perm)
		chmod(sa.sun_path, perm);
	return sock;
}

int net_udp_server(const char *bindaddr, int port, char *err, size_t errlen) {
	int sock;
	struct sockaddr_in sa;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		net_set_error(err, errlen, "creating socket: %s", strerror(errno));
		return -1;
	}
	memset(&sa, '\0', sizeof sa);
	sa.sin_family      = AF_INET;
	sa.sin_port        = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bindaddr && inet_aton(bindaddr, &sa.sin_addr) == 0) {
		net_set_error(err, errlen, "invalid bind address");
		close(sock);
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&sa, sizeof sa) == -1) {
		net_set_error(err, errlen, "bind: %s", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

int net_tcp_accept(int sock, char *ip, int *port, char *err, size_t errlen) {
	struct sockaddr_in sa;
	socklen_t len = sizeof sa;
	int fd;

	if ((fd = net_generic_accept(sock, (struct sockaddr *)&sa, &len, err, errlen)) == -1)
		return -1;
	if (ip)
		strcpy(ip, inet_ntoa(sa.sin_addr));
	if (port)
		*port = ntohs(sa.sin_port);
	return fd;
}

int net_unix_accept(int sock, char *err, size_t errlen) {
	struct sockaddr_un sa;
	socklen_t len = sizeof sa;
	int fd;

	if ((fd = net_generic_accept(sock, (struct sockaddr *)&sa, &len, err, errlen)) == -1)
		return -1;
	return fd;
}

inline int net_tcp_connect(const char *addr, int port, char *err, size_t errlen) {
	return net_tcp_generic_connect(addr, port, NET_BLOCK, err, errlen);
}

inline int net_tcp_nonblock_connect(const char *addr, int port, char *err, size_t errlen) {
	return net_tcp_generic_connect(addr, port, NET_NONBLOCK, err, errlen);
}

inline int net_unix_connect(const char *path, char *err, size_t errlen) {
	return net_unix_generic_connect(path, NET_BLOCK, err, errlen);
}

inline int net_unix_nonblock_connect(const char *path, char *err, size_t errlen) {
	return net_unix_generic_connect(path, NET_NONBLOCK, err, errlen);
}

inline int net_udp_connect(const char *addr, int port, char *err, size_t errlen) {
	return net_udp_generic_connect(addr, port, NET_BLOCK, err, errlen);
}

inline int net_udp_nonblock_connect(const char *addr, int port, char *err, size_t errlen) {
	return net_udp_generic_connect(addr, port, NET_NONBLOCK, err, errlen);
}

int net_read(int fd, char *buf, int count, int flags) {
	int len = 0, nread;

	while (len != count) {
		nread = read(fd, buf, count - len);
		if (nread == 0)
			return len;
		if (nread == -1) {
			if (flags & NET_NONBLOCK && (errno == EAGAIN || errno == EINTR))
				nread = 0;
			else
				return -1;
		}
		len += nread;
		buf += nread;
	}
	return len;
}

int net_write(int fd, const char *buf, int count, int flags) {
	int len = 0, nwrite;

	while (len != count) {
		nwrite = write(fd, buf, count - len);
		if (nwrite == 0)
			return len;
		if (nwrite == -1) {
			if (flags & NET_NONBLOCK && (errno == EAGAIN || errno == EINTR))
				nwrite = 0;
			else
				return -1;
		}
		len += nwrite;
		buf += nwrite;
	}
	return len;
}

int net_try_read(int fd, char *buf, int count, int maxtry, int flags) {
	int len = 0, nread, try = 0;

	while (len != count) {
		nread = read(fd, buf, count - len);
		if (nread == 0)
			return len;
		if (nread == -1) {
			if (flags & NET_NONBLOCK && (errno == EAGAIN || errno == EINTR) && try < maxtry) {
				nread = 0;
				++try;
			} else
				return -1;
		}
		len += nread;
		buf += nread;
	}
	return len;
}

int net_try_write(int fd, const char *buf, int count, int maxtry, int flags) {
	int len = 0, nwrite, try = 0;

	while (len != count) {
		nwrite = write(fd, buf, count - len);
		if (nwrite == 0)
			return len;
		if (nwrite == -1) {
			if (flags & NET_NONBLOCK && (errno == EAGAIN || errno == EINTR) && try < maxtry) {
				nwrite = 0;
				++try;
			} else
				return -1;
		}
		len += nwrite;
		buf += nwrite;
	}
	return len;
}

int net_nonblock(int fd, char *err, size_t errlen) {
	int flags;

	/* can't be interrupted by a signal */
	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		net_set_error(err, errlen, "fcntl(F_GETFL): %s", strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		net_set_error(err, errlen, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
		return -1;
	}
	return 0;
}

int net_tcp_nodelay(int fd, char *err, size_t errlen) {
	int on = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on) == -1) {
		net_set_error(err, errlen, "setsockopt TCP_NODELAY: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/* FIXME */
int net_tcp_keepalive(int fd, char *err, size_t errlen) {
	int on = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) == -1) {
		net_set_error(err, errlen, "setsockopt SO_KEEPALIVE: %s", strerror(errno));
		return -1;
	}
	return 0;
}

