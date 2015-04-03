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

#ifndef DLIST_INCLUDED
#define DLIST_INCLUDED

/* directions for iterators */
#define DLIST_START_HEAD 0
#define DLIST_START_TAIL 1

/* exported types */
typedef struct dlist_t      *dlist_t;
typedef struct dlist_node_t *dlist_node_t;
typedef struct dlist_iter_t *dlist_iter_t;

/* exported functions */
extern dlist_t       dlist_new(int cmp(const void *x, const void *y), void vfree(void *value));
extern void          dlist_free(dlist_t *dlp);
extern unsigned long dlist_length(dlist_t dlist);
extern dlist_node_t  dlist_head(dlist_t dlist);
extern dlist_node_t  dlist_tail(dlist_t dlist);
extern dlist_node_t  dlist_node_prev(dlist_node_t node);
extern dlist_node_t  dlist_node_next(dlist_node_t node);
extern void         *dlist_node_value(dlist_node_t node);
extern dlist_iter_t  dlist_iter_new(dlist_t dlist, int direction);
extern void          dlist_iter_free(dlist_iter_t *dlip);
extern void          dlist_iter_rewind_head(dlist_iter_t iter, dlist_t dlist);
extern void          dlist_iter_rewind_tail(dlist_iter_t iter, dlist_t dlist);
extern dlist_node_t  dlist_next(dlist_iter_t iter);
extern dlist_t       dlist_insert_head(dlist_t dlist, void *value);
extern dlist_t       dlist_insert_tail(dlist_t dlist, void *value);
extern dlist_t       dlist_insert(dlist_t dlist, dlist_node_t node, void *value, int after);
extern dlist_t       dlist_insert_sort(dlist_t dlist, void *value);
extern dlist_node_t  dlist_find(dlist_t dlist, void *value);
extern dlist_node_t  dlist_index(dlist_t dlist, long index);
extern void         *dlist_remove_head(dlist_t dlist);
extern void         *dlist_remove_tail(dlist_t dlist);
extern void         *dlist_remove(dlist_t dlist, dlist_node_t node);
extern dlist_t       dlist_append(dlist_t dlist, dlist_t tail);
extern dlist_t       dlist_copy(dlist_t dlist);
extern void          dlist_rotate(dlist_t dlist);
extern void          dlist_lock(dlist_t dlist);
extern void          dlist_unlock(dlist_t dlist);
extern void          dlist_rwlock_rdlock(dlist_t dlist);
extern void          dlist_rwlock_wrlock(dlist_t dlist);
extern void          dlist_rwlock_unlock(dlist_t dlist);

#endif /* DLIST_INCLUDED */

