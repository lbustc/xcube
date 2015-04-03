/*
 * Copyright (c) 2013-2015, Dalian Futures Information Technology Co., Ltd.
 *
 * Guodong Zhang <zhangguodong at dce dot com dot cn>
 * Xiaoye Meng   <mengxiaoye at dce dot com dot cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef STL_INCLUDED
#define STL_INCLUDED

#ifdef __cplusplus
extern "C"{
#endif

#include <stdbool.h>

/* exported types */
typedef struct vec_t      vec_t;
typedef struct deq_t      deq_t;
typedef struct map_t      map_t;
typedef struct map_iter_t map_iter_t;

/* FIXME: exported functions */
extern vec_t      *vec_create();
extern void        vec_destroy(vec_t *vec);
extern unsigned    vec_size(vec_t *vec);
extern bool        vec_empty(vec_t *vec);
extern unsigned    vec_max_size(vec_t *vec);
extern void       *vec_at(vec_t *vec, unsigned pos);
extern void       *vec_front(vec_t *vec);
extern void       *vec_back(vec_t *vec);
extern void        vec_push_back(vec_t *vec, void *item);
extern void        vec_pop_back(vec_t *vec);
extern void        vec_erase(vec_t *vec, unsigned pos);
extern void        vec_resize(vec_t *vec, unsigned num);
extern void        vec_clear(vec_t *vec);
extern deq_t      *deq_create();
extern void        deq_destroy(deq_t *deq);
extern unsigned    deq_size(deq_t *deq);
extern bool        deq_empty(deq_t *deq);
extern unsigned    deq_max_size(deq_t *deq);
extern void       *deq_at(deq_t *deq, unsigned pos);
extern void       *deq_front(deq_t *deq);
extern void       *deq_back(deq_t *deq);
extern void        deq_push_back(deq_t *deq, void *item);
extern void        deq_pop_back(deq_t *deq);
extern void        deq_push_front(deq_t *deq, void *item);
extern void        deq_pop_front(deq_t *deq);
extern void        deq_erase(deq_t *deq, unsigned pos);
extern void        deq_resize(deq_t *deq, unsigned num);
extern void        deq_clear(deq_t *deq);
extern map_t      *map_create();
extern void        map_destroy(map_t *map);
extern unsigned    map_size(map_t *map);
extern bool        map_empty(map_t *map);
extern unsigned    map_max_size(map_t *map);
extern map_iter_t *map_iter_create();
extern void        map_iter_destroy(map_iter_t *map_iter);
extern void        map_begin(map_iter_t *map_iter, map_t *map);
extern void        map_find(map_iter_t *map_iter, map_t *map, const char *key);
extern bool        map_iter_valid(map_iter_t *map_iter, map_t *map);
extern void        map_iter_next(map_iter_t *map_iter);
extern void        map_iter_prev(map_iter_t *map_iter);
extern const char *map_iter_key(map_iter_t *map_iter);
extern void       *map_iter_value(map_iter_t *map_iter);
extern void        map_insert(map_t *map, const char *key, void *value);
extern unsigned    map_erase(map_t *map, const char *key);
extern void        map_clear(map_t *map);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif /* STL_INCLUDED */

