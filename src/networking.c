/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
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

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include "macros.h"
#include "mem.h"
#include "dlist.h"
#include "logger.h"
#include "event.h"
#include "commons.h"

/* FIXME */
extern dlist_t clients_to_close;
extern event_loop el;

/* FIXME */
extern void client_free(client c);
extern void process_inbuf(client c);

inline void client_incr(client c) {
	if (c)
		__sync_fetch_and_add(&c->refcount, 1);
}

void client_decr(client c) {
	int ret, val;

	if (c == NULL)
		return;
	ret = __sync_fetch_and_add(&c->refcount, -1);
	if ((val = ret - 1) < 0)
		xcb_log(XCB_LOG_WARNING, "Invalid refcount %d on client '%p'", val, c);
}

void client_free_async(client c) {
	if (c->flags & CLIENT_CLOSE_ASAP)
		return;
	c->flags |= CLIENT_CLOSE_ASAP;
	dlist_insert_tail(clients_to_close, c);
}

static void send_to_client(event_loop el, int fd, int mask, void *data) {
	client c = (client)data;
	int nwritten = 0, totwritten = 0;
	NOT_USED(el);
	NOT_USED(mask);

	while (c->outpos > 0 || ring_length(c->reply) > 0) {
		if (c->outpos > 0) {
			pthread_spin_lock(&c->lock);
			nwritten = write(fd, c->outbuf + c->sentlen, c->outpos - c->sentlen);
			pthread_spin_unlock(&c->lock);
			if (nwritten <= 0)
				break;
			c->sentlen += nwritten;
			totwritten += nwritten;
			if (c->sentlen == c->outpos)
				c->sentlen = c->outpos = 0;
		} else {
			char *p = ring_get(c->reply, 0);
			int len;

			if ((len = strlen(p)) == 0) {
				ring_remlo(c->reply);
				FREE(p);
				continue;
			}
			pthread_spin_lock(&c->lock);
			nwritten = write(fd, p + c->sentlen, len - c->sentlen);
			pthread_spin_unlock(&c->lock);
			if (nwritten <= 0)
				break;
			c->sentlen += nwritten;
			totwritten += nwritten;
			if (c->sentlen == len) {
				ring_remlo(c->reply);
				FREE(p);
				c->sentlen = 0;
			}
		}
		/* FIXME */
		if (totwritten > 2 * 1024)
			break;
	}
	if (nwritten < 0) {
		if (errno == EAGAIN || errno == EINTR)
			nwritten = 0;
		else {
			xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s", c, strerror(errno));
			if (c->refcount == 0)
				client_free(c);
			return;
		}
	}
	if (c->outpos == 0 && ring_length(c->reply) == 0) {
		c->sentlen = 0;
		delete_file_event(el, c->fd, EVENT_WRITABLE);
		if (c->flags & CLIENT_CLOSE_AFTER_REPLY && c->refcount == 0)
			client_free(c);
	}
}

static int prepare_to_write(client c) {
	if (c->fd <= 0)
		return -1;
	if (c->outpos == 0 && ring_length(c->reply) == 0 &&
		create_file_event(el, c->fd, EVENT_WRITABLE, send_to_client, c) == -1)
		return -1;
	return 0;
}

static int add_reply_to_buffer(client c, const char *str, size_t len) {
	size_t avail = sizeof c->outbuf - c->outpos;

	if (c->flags & CLIENT_CLOSE_AFTER_REPLY)
		return 0;
	if (ring_length(c->reply) > 0)
		return -1;
	if (len > avail)
		return -1;
	memcpy(c->outbuf + c->outpos, str, len);
	c->outpos += len;
	return 0;
}

static void add_reply_to_list(client c, const char *str, size_t len) {
	char *p;

	if (c->flags & CLIENT_CLOSE_AFTER_REPLY)
		return;
	if ((p = ALLOC(len + 1)) == NULL)
		return;
	memcpy(p, str, len);
	p[len] = '\0';
	ring_addhi(c->reply, p);
}

void add_reply_string(client c, const char *str, size_t len) {
	if (prepare_to_write(c) == -1)
		return;
	if (add_reply_to_buffer(c, str, len) == -1)
		add_reply_to_list(c, str, len);
}

/* FIXME */
void add_reply_string_format(client c, const char *fmt, ...) {
	va_list ap;
	char buf[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	add_reply_string(c, buf, strlen(buf));
}

void add_reply_error(client c, const char *err) {
	add_reply_string(c, "-ERR ", 5);
	add_reply_string(c, err, strlen(err));
	add_reply_string(c, "\r\n", 2);
}

/* FIXME */
void add_reply_error_format(client c, const char *fmt, ...) {
	va_list ap;
	char buf[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	add_reply_error(c, buf);
}

void read_from_client(event_loop el, int fd, int mask, void *data) {
	client c = (client)data;
	int nread;
	NOT_USED(el);
	NOT_USED(mask);

	if ((nread = read(fd, c->inbuf + c->inpos, sizeof c->inbuf - c->inpos)) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			nread = 0;
		else {
			xcb_log(XCB_LOG_WARNING, "Reading from client '%p': %s", c, strerror(errno));
			if (c->refcount == 0)
				client_free(c);
			return;
		}
	} else if (nread == 0) {
		xcb_log(XCB_LOG_WARNING, "Client '%p' closed connection", c);
		if (c->refcount == 0)
			client_free(c);
		return;
	}
	if (nread)
		c->inpos += nread;
	else
		return;
	if (c->inpos >= sizeof c->inbuf) {
		xcb_log(XCB_LOG_WARNING, "Closing client '%p' that reached max input buffer length", c);
		if (c->refcount == 0)
			client_free(c);
		return;
	}
	c->inbuf[c->inpos] = '\0';
	process_inbuf(c);
}

