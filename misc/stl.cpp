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

#include <cstring>
#include <deque>
#include <map>
#include <vector>
#include "stl.h"

extern "C" {

/* FIXME */
struct cmpstr {
	bool operator()(const char *x, const char *y) {
		return std::strcmp(x, y) < 0;
	}
};
struct vec_t      { std::vector<void *>                             *rep; };
struct deq_t      { std::deque<void *>                              *rep; };
struct map_t      { std::map<const char *, void *, cmpstr>          *rep; };
struct map_iter_t { std::map<const char *, void *, cmpstr>::iterator rep; };

vec_t *vec_create() {
	vec_t *vec;

	if ((vec = new vec_t) == NULL)
		return NULL;
	if ((vec->rep = new std::vector<void *>()) == NULL) {
		delete vec;
		return NULL;
	}
	return vec;
}

void vec_destroy(vec_t *vec) {
	if (vec == NULL)
		return;
	delete vec->rep;
	delete vec;
}

unsigned vec_size(vec_t *vec) {
	if (vec == NULL)
		return 0;
	return vec->rep->size();
}

bool vec_empty(vec_t *vec) {
	if (vec == NULL)
		return true;
	return vec->rep->empty();
}

unsigned vec_max_size(vec_t *vec) {
	if (vec == NULL)
		return 0;
	return vec->rep->max_size();
}

void *vec_at(vec_t *vec, unsigned pos) {
	if (vec == NULL)
		return NULL;
	if (pos > vec->rep->size() - 1)
		return NULL;
	return vec->rep->at(pos);
}

void *vec_front(vec_t *vec) {
	if (vec == NULL)
		return NULL;
	return vec->rep->front();
}

void *vec_back(vec_t *vec) {
	if (vec == NULL)
		return NULL;
	return vec->rep->back();
}

void vec_push_back(vec_t *vec, void *item) {
	if (vec == NULL)
		return;
	return vec->rep->push_back(item);
}

void vec_pop_back(vec_t *vec) {
	if (vec == NULL)
		return;
	return vec->rep->pop_back();
}

void vec_erase(vec_t *vec, unsigned pos) {
	unsigned i = 0;

	if (vec == NULL)
		return;
	for (std::vector<void *>::iterator it = vec->rep->begin(); it != vec->rep->end(); ++it, ++i)
		if (i == pos) {
			vec->rep->erase(it);
			break;
		}
}

void vec_resize(vec_t *vec, unsigned num) {
	if (vec == NULL)
		return;
	vec->rep->resize(num);
}

void vec_clear(vec_t *vec) {
	if (vec == NULL)
		return;
	vec->rep->clear();
}

deq_t *deq_create() {
	deq_t *deq;

	if ((deq = new deq_t) == NULL)
		return NULL;
	if ((deq->rep = new std::deque<void *>()) == NULL) {
		delete deq;
		return NULL;
	}
	return deq;
}

void deq_destroy(deq_t *deq) {
	if (deq == NULL)
		return;
	delete deq->rep;
	delete deq;
}

unsigned deq_size(deq_t *deq) {
	if (deq == NULL)
		return 0;
	return deq->rep->size();
}

bool deq_empty(deq_t *deq) {
	if (deq == NULL)
		return true;
	return deq->rep->empty();
}

unsigned deq_max_size(deq_t *deq) {
	if (deq == NULL)
		return 0;
	return deq->rep->max_size();
}

void *deq_at(deq_t *deq, unsigned pos) {
	if (deq == NULL)
		return NULL;
	if (pos > deq->rep->size() - 1)
		return NULL;
	return deq->rep->at(pos);
}

void *deq_front(deq_t *deq) {
	if (deq == NULL)
		return NULL;
	return deq->rep->front();
}

void *deq_back(deq_t *deq) {
	if (deq == NULL)
		return NULL;
	return deq->rep->back();
}

void deq_push_back(deq_t *deq, void *item) {
	if (deq == NULL)
		return;
	return deq->rep->push_back(item);
}

void deq_pop_back(deq_t *deq) {
	if (deq == NULL)
		return;
	return deq->rep->pop_back();
}

void deq_push_front(deq_t *deq, void *item) {
	if (deq == NULL)
		return;
	return deq->rep->push_front(item);
}

void deq_pop_front(deq_t *deq) {
	if (deq == NULL)
		return;
	return deq->rep->pop_front();
}

void deq_erase(deq_t *deq, unsigned pos) {
	unsigned i = 0;

	if (deq == NULL)
		return;
	for (std::deque<void *>::iterator it = deq->rep->begin(); it != deq->rep->end(); ++it, ++i)
		if (i == pos) {
			deq->rep->erase(it);
			break;
		}
}

void deq_resize(deq_t *deq, unsigned num) {
	if (deq == NULL)
		return;
	deq->rep->resize(num);
}

void deq_clear(deq_t *deq) {
	if (deq == NULL)
		return;
	deq->rep->clear();
}

map_t *map_create() {
	map_t *map;

	if ((map = new map_t) == NULL)
		return NULL;
	if ((map->rep = new std::map<const char *, void *, cmpstr>()) == NULL) {
		delete map;
		return NULL;
	}
	return map;
}

void map_destroy(map_t *map) {
	if (map == NULL)
		return;
	delete map->rep;
	delete map;
}

unsigned map_size(map_t *map) {
	if (map == NULL)
		return 0;
	return map->rep->size();
}

bool map_empty(map_t *map) {
	if (map == NULL)
		return true;
	return map->rep->empty();
}

unsigned map_max_size(map_t *map) {
	if (map == NULL)
		return 0;
	return map->rep->max_size();
}

/* FIXME */
map_iter_t *map_iter_create() {
	return new map_iter_t;
}

void map_iter_destroy(map_iter_t *map_iter) {
	if (map_iter == NULL)
		return;
	delete map_iter;
}

void map_begin(map_iter_t *map_iter, map_t *map) {
	if (map_iter == NULL || map == NULL)
		return;
	map_iter->rep = map->rep->begin();
}

void map_find(map_iter_t *map_iter, map_t *map, const char *key) {
	if (map_iter == NULL || map == NULL)
		return;
	map_iter->rep = map->rep->find(key);
}

bool map_iter_valid(map_iter_t *map_iter, map_t *map) {
	if (map_iter == NULL || map == NULL)
		return false;
	return map_iter->rep != map->rep->end();
}

void map_iter_next(map_iter_t *map_iter) {
	if (map_iter == NULL)
		return;
	++map_iter->rep;
}

void map_iter_prev(map_iter_t *map_iter) {
	if (map_iter == NULL)
		return;
	--map_iter->rep;
}

const char *map_iter_key(map_iter_t *map_iter) {
	return map_iter->rep->first;
}

void *map_iter_value(map_iter_t *map_iter) {
	return map_iter->rep->second;
}

void map_insert(map_t *map, const char *key, void *value) {
	if (map == NULL)
		return;
	map->rep->insert(std::pair<const char *, void *>(key, value));
}

unsigned map_erase(map_t *map, const char *key) {
	if (map == NULL)
		return 0;
	return map->rep->erase(key);
}

void map_clear(map_t *map) {
	if (map == NULL)
		return;
	map->rep->clear();
}

}

