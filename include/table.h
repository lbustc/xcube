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

#ifndef TABLE_INCLUDED
#define TABLE_INCLUDED

/* FIXME */
#define TABLE_INIT_SIZE 64

/* exported types */
typedef struct table_t      *table_t;
typedef struct table_node_t *table_node_t;
typedef struct table_iter_t *table_iter_t;

/* exported functions */
extern table_t       table_new(int cmp(const void *x, const void *y), unsigned hash(const void *key),
			void kfree(const void *key), void vfree(void *value));
extern void          table_free(table_t *tp);
extern unsigned long table_size(table_t table);
extern unsigned long table_length(table_t table);
extern const void   *table_node_key(table_node_t node);
extern void         *table_node_value(table_node_t node);
extern int           table_node_int(table_node_t node);
extern float         table_node_float(table_node_t node);
extern double        table_node_double(table_node_t node);
extern table_iter_t  table_iter_new(table_t table);
extern table_iter_t  table_iter_safe_new(table_t table);
extern void          table_iter_free(table_iter_t *tip);
extern void          table_iter_rewind(table_iter_t iter);
extern table_node_t  table_next(table_iter_t iter);
extern int           table_expand(table_t table, unsigned long size);
extern int           table_resize(table_t table);
extern void          table_resize_enable(void);
extern void          table_resize_disable(void);
extern table_node_t  table_insert_raw(table_t table, const void *key);
extern void          table_set_value(table_node_t node, void *value);
extern void          table_set_int(table_node_t node, int i);
extern void          table_set_float(table_node_t node, float f);
extern void          table_set_double(table_node_t node, double d);
extern void         *table_insert(table_t table, const void *key, void *value);
extern table_node_t  table_find(table_t table, const void *key);
extern void         *table_get_value(table_t table, const void *key);
extern void         *table_remove(table_t table, const void *key);
extern void          table_clear(table_t table);
extern int           table_rehash(table_t table, int n);
extern void          table_rehash_ms(table_t table, int ms);
extern void          table_lock(table_t table);
extern void          table_unlock(table_t table);
extern void          table_rwlock_rdlock(table_t table);
extern void          table_rwlock_wrlock(table_t table);
extern void          table_rwlock_unlock(table_t table);

#endif /* TABLE_INCLUDED */

