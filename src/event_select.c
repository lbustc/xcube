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

#include <string.h>
#include <sys/select.h>
#include "mem.h"

typedef struct api_state {
	fd_set	rfds, wfds;
	/* It's not safe to reuse fd sets after select(). */
	fd_set	_rfds, _wfds;
} *api_state;

static int api_create(event_loop el) {
	api_state state;

	if (NEW(state) == NULL)
		return -1;
	FD_ZERO(&state->rfds);
	FD_ZERO(&state->wfds);
	el->apidata = state;
	return 0;
}

static void api_free(event_loop el) {
	if (el)
		FREE(el->apidata);
}

static int api_add_event(event_loop el, int fd, int mask) {
	api_state state = el->apidata;

	if (mask & EVENT_READABLE)
		FD_SET(fd, &state->rfds);
	if (mask & EVENT_WRITABLE)
		FD_SET(fd, &state->wfds);
	return 0;
}

static void api_del_event(event_loop el, int fd, int mask) {
	api_state state = el->apidata;

	if (mask & EVENT_READABLE)
		FD_CLR(fd, &state->rfds);
	if (mask & EVENT_WRITABLE)
		FD_CLR(fd, &state->wfds);
}

static int api_poll(event_loop el, struct timeval *timeout) {
	api_state state = el->apidata;
	int nevents = 0;

	memcpy(&state->_rfds, &state->rfds, sizeof state->rfds);
	memcpy(&state->_wfds, &state->wfds, sizeof state->wfds);
	if (select(el->maxfd + 1, &state->_rfds, &state->_wfds, NULL, timeout) > 0) {
		int i;

		for (i = 0; i <= el->maxfd; ++i) {
			file_event fe = &el->fevents[i];
			int mask = 0;

			if (fe->mask == EVENT_NONE)
				continue;
			if (fe->mask & EVENT_READABLE && FD_ISSET(i, &state->_rfds))
				mask |= EVENT_READABLE;
			if (fe->mask & EVENT_WRITABLE && FD_ISSET(i, &state->_wfds))
				mask |= EVENT_WRITABLE;
			el->fireds[nevents].fd   = i;
			el->fireds[nevents].mask = mask;
			++nevents;
		}
	}
	return nevents;
}

