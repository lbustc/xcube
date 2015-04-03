/*
 * Copyright (C) 2009, Digium, Inc.
 *
 * Russell Bryant <russell@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include <pthread.h>
#include "mem.h"
#include "heap.h"

/* FIXME */
struct heap_t {
	unsigned long	avail, curr;
	void		**h;
	ssize_t		offset;
	int		(*cmp)(const void *x, const void *y);
	pthread_mutex_t	lock;
};

static inline unsigned left_node(unsigned i) {
	return i << 1;
}

static inline unsigned right_node(unsigned i) {
	return (i << 1) + 1;
}

static inline unsigned parent_node(unsigned i) {
	return i / 2;
}

static inline void *heap_get(heap_t heap, unsigned long i) {
	return heap->h[i - 1];
}

static void heap_set(heap_t heap, unsigned long i, void *elem) {
	heap->h[i - 1] = elem;
	if (heap->offset >= 0) {
		unsigned long *ip = elem + heap->offset;

		*ip = i;
	}
}

static unsigned long get_index(heap_t heap, void *elem) {
	unsigned long *ip;

	if (heap->offset < 0)
		return 0;
	ip = elem + heap->offset;
	return *ip;
}

static void heap_swap(heap_t heap, unsigned long i, unsigned long j) {
	void *tmp;

	tmp = heap_get(heap, i);
	heap_set(heap, i, heap_get(heap, j));
	heap_set(heap, j, tmp);
}

static int grow_heap(heap_t heap) {
	heap->avail = (heap->avail << 1) + 1;
	if (RESIZE(heap->h, heap->avail * sizeof *heap->h) == NULL) {
		heap->curr = heap->avail = 0;
		return -1;
	}
	return 0;
}

static unsigned bubble_up(heap_t heap, unsigned long i) {
	while (i > 1 && heap->cmp(heap_get(heap, parent_node(i)), heap_get(heap, i)) < 0) {
		heap_swap(heap, parent_node(i), i);
		i = parent_node(i);
	}
	return i;
}

static void max_heapify(heap_t heap, unsigned long i) {
	for (;;) {
		unsigned long l = left_node(i), r = right_node(i), max;

		max = l <= heap->curr && heap->cmp(heap_get(heap, l), heap_get(heap, i)) > 0
			? l : i;
		if (r <= heap->curr && heap->cmp(heap_get(heap, r), heap_get(heap, max)) > 0)
			max = r;
		if (max == i)
			break;
		heap_swap(heap, i, max);
		i = max;
	}
}

static void *_heap_remove(heap_t heap, unsigned long i) {
	void *ret;

	if (i > heap->curr)
		return NULL;
	ret = heap_get(heap, i);
	heap_set(heap, i, heap_get(heap, heap->curr--));
	i = bubble_up(heap, i);
	max_heapify(heap, i);
	return ret;
}

/* The 'offset' parameter is optional, but must be provided to be able to use heap_remove().
 * If heap_remove() will not be used, then a negative value can be provided.
 */
heap_t heap_new(int height, ssize_t offset, int cmp(const void *x, const void *y)) {
	heap_t heap;
	pthread_mutexattr_t attr;

	if (height <= 0)
		height = 8;
	if (cmp == NULL)
		return NULL;
	if (NEW(heap) == NULL)
		return NULL;
	heap->avail  = (height << 1) - 1;
	heap->curr   = 0;
	if ((heap->h = CALLOC(1, heap->avail * sizeof *heap->h)) == NULL) {
		FREE(heap);
		return NULL;
	}
	heap->offset = offset;
	heap->cmp    = cmp;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&heap->lock, &attr);
	pthread_mutexattr_destroy(&attr);
	return heap;
}

void heap_free(heap_t *hp) {
	if (hp == NULL || *hp == NULL)
		return;
	pthread_mutex_destroy(&(*hp)->lock);
	FREE((*hp)->h);
	FREE(*hp);
}

unsigned long heap_length(heap_t heap) {
	if (heap == NULL)
		return 0;
	return heap->curr;
}

/* Return 0 if success, otherwise -1 is returned */
int heap_push(heap_t heap, void *elem) {
	if (heap == NULL || elem == NULL)
		return -1;
	if (heap->curr == heap->avail && grow_heap(heap))
		return -1;
	heap_set(heap, ++heap->curr, elem);
	bubble_up(heap, heap->curr);
	return 0;
}

void *heap_pop(heap_t heap) {
	if (heap == NULL)
		return NULL;
	return _heap_remove(heap, 1);
}

void *heap_remove(heap_t heap, void *elem) {
	unsigned long i;

	if (heap == NULL || elem == NULL)
		return NULL;
	if ((i = get_index(heap, elem)) == 0)
		return NULL;
	return _heap_remove(heap, i);
}

void *heap_peek(heap_t heap, unsigned long index) {
	if (heap == NULL)
		return NULL;
	if (heap->curr == 0 || index == 0 || index > heap->curr)
		return NULL;
	return heap_get(heap, index);
}

void heap_lock(heap_t heap) {
	if (heap == NULL)
		return;
	pthread_mutex_lock(&heap->lock);
}

void heap_unlock(heap_t heap) {
	if (heap == NULL)
		return;
	pthread_mutex_unlock(&heap->lock);
}

