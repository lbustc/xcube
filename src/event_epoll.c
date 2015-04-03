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
 * revised by xiaoyem
 */

#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "mem.h"

typedef struct api_state {
	int			epfd;
	struct epoll_event	*events;
} *api_state;

static int api_create(event_loop el) {
	api_state state;

	if (NEW(state) == NULL)
		return -1;
	if ((state->events = ALLOC(el->size * sizeof (struct epoll_event))) == NULL) {
		FREE(state);
		return -1;
	}
	/* 1024 is just a hint for the kernel */
	if ((state->epfd = epoll_create(1024)) == -1) {
		FREE(state->events);
		FREE(state);
		return -1;
	}
	el->apidata = state;
	return 0;
}

static void api_free(event_loop el) {
	api_state state = el->apidata;

	if (state) {
		close(state->epfd);
		FREE(state->events);
		FREE(state);
	}
}

static int api_add_event(event_loop el, int fd, int mask) {
	struct epoll_event ee;
	api_state state = el->apidata;
	int op = el->fevents[fd].mask == EVENT_NONE ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

	ee.events = 0;
	/* merge old events */
	mask |= el->fevents[fd].mask;
	if (mask & EVENT_READABLE)
		ee.events |= EPOLLIN;
	if (mask & EVENT_WRITABLE)
		ee.events |= EPOLLOUT;
	/* FIXME */
	ee.data.u64 = 0;
	ee.data.fd  = fd;
	if (epoll_ctl(state->epfd, op, fd, &ee) == -1)
		return -1;
	return 0;
}

static void api_del_event(event_loop el, int fd, int delmask) {
	struct epoll_event ee;
	int mask = el->fevents[fd].mask & ~delmask;
	api_state state = el->apidata;

	ee.events = 0;
	if (mask & EVENT_READABLE)
		ee.events |= EPOLLIN;
	if (mask & EVENT_WRITABLE)
		ee.events |= EPOLLOUT;
	/* FIXME */
	ee.data.u64 = 0;
	ee.data.fd  = fd;
	mask != EVENT_NONE ? epoll_ctl(state->epfd, EPOLL_CTL_MOD, fd, &ee)
			: epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, &ee);
}

static int api_poll(event_loop el, struct timeval *timeout) {
	api_state state = el->apidata;
	int nevents = 0;

	if ((nevents = epoll_wait(state->epfd, state->events, el->size,
				timeout ? (timeout->tv_sec * 1000 + timeout->tv_usec / 1000) : -1)) > 0) {
		int i;

		for (i = 0; i < nevents; ++i) {
			struct epoll_event *eep = &state->events[i];
			int mask = 0;

			if (eep->events & EPOLLIN)
				mask |= EVENT_READABLE;
			if (eep->events & EPOLLOUT)
				mask |= EVENT_WRITABLE;
			if (eep->events & EPOLLERR)
				mask |= EVENT_WRITABLE;
			if (eep->events & EPOLLHUP)
				mask |= EVENT_WRITABLE;
			el->fireds[i].fd   = eep->data.fd;
			el->fireds[i].mask = mask;
		}
	}
	return nevents;
}

