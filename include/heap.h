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

#ifndef HEAP_INCLUDED
#define HEAP_INCLUDED

#include <unistd.h>

/* exported types */
typedef struct heap_t *heap_t;

/* exported functions */
extern heap_t        heap_new(int height, ssize_t offset, int cmp(const void *x, const void *y));
extern void          heap_free(heap_t *hp);
extern unsigned long heap_length(heap_t heap);
extern int           heap_push(heap_t heap, void *elem);
extern void         *heap_pop(heap_t heap);
extern void         *heap_remove(heap_t heap, void *elem);
extern void         *heap_peek(heap_t heap, unsigned long index);
extern void          heap_lock(heap_t heap);
extern void          heap_unlock(heap_t heap);

#endif /* HEAP_INCLUDED */

