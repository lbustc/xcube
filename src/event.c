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

#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include "mem.h"
#include "heap.h"
#include "event.h"

struct file_event {
	int		mask;
	file_proc	*rproc, *wproc;
	void		*data;
};
typedef struct fired_event {
	int		fd;
	int		mask;
} *fired_event;
struct time_event {
	/* time event identifier */
	unsigned long	id;
	long		sec, ms;
	time_proc	*tproc;
	finalizer	*f;
	void		*data;
};
struct event_loop {
	int		size;
	int		maxfd;
	time_t		lasttime;
	int		stop;
	int		safe;
	file_event	fevents;
	fired_event	fireds;
	heap_t		tevent;
	void		*apidata;
};

/* FIXME */
#ifdef __linux__
#include "event_epoll.c"
#else
#include "event_select.c"
#endif

/* FIXME */
static int tecmp(const void *x, const void *y) {
	time_event a = (time_event)x, b = (time_event)y;

	if (a->sec > b->sec)
		return -1;
	if (a->sec < b->sec)
		return 1;
	if (a->ms > b->ms)
		return -1;
	if (a->ms < b->ms)
		return 1;
	return 0;
}

static void add_ms_to_now(long long msecs, long *sec, long *ms) {
	struct timeval tv;
	long when_sec, when_ms;

	gettimeofday(&tv, NULL);
	when_sec = tv.tv_sec + msecs / 1000;
	when_ms = tv.tv_usec / 1000 + msecs % 1000;
	if (when_ms > 1000) {
		++when_sec;
		when_ms -= 1000;
	}
	*sec = when_sec;
	*ms = when_ms;
}

/* FIXME */
static time_event search_nearest_timer(event_loop el) {
	time_event nearest = NULL;

	if (el->safe)
		heap_lock(el->tevent);
	nearest = heap_peek(el->tevent, 1);
	if (el->safe)
		heap_unlock(el->tevent);
	return nearest;
}

event_loop create_event_loop(int size) {
	event_loop el;
	int i;

	if (NEW(el) == NULL)
		return NULL;
	el->size     = size;
	el->maxfd    = -1;
	el->lasttime = time(NULL);
	el->stop     = 0;
	el->safe     = 0;
	if ((el->fevents = ALLOC(size * sizeof (struct file_event))) == NULL)
		goto err;
	if ((el->fireds = ALLOC(size * sizeof (struct fired_event))) == NULL)
		goto err;
	if ((el->tevent = heap_new(8, offsetof(struct time_event, id), tecmp)) == NULL)
		goto err;
	if (api_create(el) == -1)
		goto err;
	for (i = 0; i < size; ++i)
		el->fevents[i].mask = EVENT_NONE;
	return el;

err:
	if (el) {
		FREE(el->fevents);
		FREE(el->fireds);
		heap_free(&el->tevent);
		FREE(el);
	}
	return NULL;
}

event_loop create_event_loop_safe(int size) {
	event_loop el = create_event_loop(size);

	if (el)
		el->safe = 1;
	return el;
}

/* FIXME */
void delete_event_loop(event_loop el) {
	if (el) {
		api_free(el);
		heap_free(&el->tevent);
		FREE(el->fireds);
		FREE(el->fevents);
		FREE(el);
	}
}

int create_file_event(event_loop el, int fd, int mask, file_proc *proc, void *data) {
	file_event fe;

	/* FIXME */
	if (el == NULL)
		return -1;
	if (fd >= el->size) {
		errno = ERANGE;
		return -1;
	}
	if (api_add_event(el, fd, mask) == -1)
		return -1;
	fe = &el->fevents[fd];
	fe->mask |= mask;
	if (mask & EVENT_READABLE)
		fe->rproc = proc;
	if (mask & EVENT_WRITABLE)
		fe->wproc = proc;
	fe->data = data;
	if (fd > el->maxfd)
		el->maxfd = fd;
	return 0;
}

void delete_file_event(event_loop el, int fd, int mask) {
	file_event fe;

	if (el == NULL)
		return;
	if (fd >= el->size)
		return;
	fe = &el->fevents[fd];
	if (fe->mask == EVENT_NONE)
		return;
	fe->mask = fe->mask & ~mask;
	/* update maxfd */
	if (fd == el->maxfd && fe->mask == EVENT_NONE) {
		int i;

		for (i = el->maxfd - 1; i >= 0; --i)
			if (el->fevents[i].mask != EVENT_NONE)
				break;
		el->maxfd = i;
	}
	api_del_event(el, fd, mask);
}

unsigned long create_time_event(event_loop el, long long ms, time_proc *proc, finalizer *f, void *data) {
	time_event te;

	if (el == NULL)
		return -1;
	if (NEW(te) == NULL)
		return -1;
	add_ms_to_now(ms, &te->sec, &te->ms);
	te->tproc = proc;
	te->f     = f;
	te->data  = data;
	if (el->safe)
		heap_lock(el->tevent);
	if (heap_push(el->tevent, te) == -1) {
		FREE(te);
		if (el->safe)
			heap_unlock(el->tevent);
		return -1;
	}
	if (el->safe)
		heap_unlock(el->tevent);
	return te->id;
}

int delete_time_event(event_loop el, unsigned long id) {
	time_event te;

	if (el == NULL)
		return -1;
	if (el->safe)
		heap_lock(el->tevent);
	if ((te = heap_remove(el->tevent, heap_peek(el->tevent, id)))) {
		if (te->f)
			te->f(el, te->data);
		FREE(te);
		if (el->safe)
			heap_unlock(el->tevent);
		return 0;
	}
	if (el->safe)
		heap_unlock(el->tevent);
	return -1;
}

int process_events(event_loop el, int flags) {
	struct timeval tv;
	int processed = 0;

	if (el == NULL)
		return 0;
	if (!(flags & FILE_EVENTS) && !(flags & TIME_EVENTS))
		return 0;
	if (el->maxfd != -1 || (flags & TIME_EVENTS && !(flags & DONT_WAIT))) {
		time_event nearest = NULL;
		struct timeval *timeout = NULL;
		int nevents, i;

		if (flags & TIME_EVENTS && !(flags & DONT_WAIT))
			nearest = search_nearest_timer(el);
		if (nearest) {
			/* calculate the time missing for the nearest timer to fire */
			gettimeofday(&tv, NULL);
			timeout = &tv;
			timeout->tv_sec = nearest->sec - timeout->tv_sec;
			if (nearest->ms < timeout->tv_usec / 1000) {
				timeout->tv_usec = (nearest->ms + 1000 - timeout->tv_usec / 1000) * 1000;
				--timeout->tv_sec;
			} else
				timeout->tv_usec = (nearest->ms - timeout->tv_usec / 1000) * 1000;
			if (timeout->tv_sec < 0)
				timeout->tv_sec = 0;
			if (timeout->tv_usec < 0)
				timeout->tv_usec = 0;
		} else if (flags & DONT_WAIT) {
			timeout = &tv;
			timeout->tv_usec = timeout->tv_sec = 0;
		}
		nevents = api_poll(el, timeout);
		for (i = 0; i < nevents; ++i) {
			file_event fe = &el->fevents[el->fireds[i].fd];
			int rfired = 0;

			/* FIXME */
			if (fe->mask & el->fireds[i].mask & EVENT_READABLE) {
				rfired = 1;
				fe->rproc(el, el->fireds[i].fd, el->fireds[i].mask, fe->data);
			}
			if (fe->mask & el->fireds[i].mask & EVENT_WRITABLE)
				if (!rfired || fe->wproc != fe->rproc)
					fe->wproc(el, el->fireds[i].fd, el->fireds[i].mask, fe->data);
			++processed;
		}
	}
	if (flags & TIME_EVENTS) {
		time_t now = time(NULL);
		time_event te;

		/* FIXME */
		if (now < el->lasttime) {
			unsigned long size, i;

			if (el->safe)
				heap_lock(el->tevent);
			size = heap_length(el->tevent);
			for (i = 1; i <= size && (te = heap_peek(el->tevent, i)); ++i)
				te->sec = 0;
			if (el->safe)
				heap_unlock(el->tevent);
		}
		el->lasttime = now;
		if (el->safe)
			heap_lock(el->tevent);
		while ((te = heap_peek(el->tevent, 1))) {
			int ret;

			gettimeofday(&tv, NULL);
			if (tv.tv_sec < te->sec || (tv.tv_sec == te->sec && tv.tv_usec / 1000 < te->ms))
				break;
			te = heap_pop(el->tevent);
			/* FIXME */
			if ((ret = te->tproc(el, te->id, te->data)) != EVENT_NOMORE) {
				add_ms_to_now(ret, &te->sec, &te->ms);
				heap_push(el->tevent, te);
			} else {
				if (te->f)
					te->f(el, te->data);
				FREE(te);
			}
			++processed;
		}
		if (el->safe)
			heap_unlock(el->tevent);
	}
	return processed;
}

void start_event_loop(event_loop el, int flags) {
	if (el == NULL)
		return;
	el->stop = 0;
	while (!el->stop)
		process_events(el, flags);
}

void stop_event_loop(event_loop el) {
	if (el == NULL)
		return;
	el->stop = 1;
}

