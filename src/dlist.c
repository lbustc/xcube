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

#include <pthread.h>
#include "mem.h"
#include "dlist.h"

/* FIXME */
struct dlist_t {
	unsigned long		length;
	dlist_node_t		head, tail;
	int			(*cmp)(const void *x, const void *y);
	void			(*vfree)(void *value);
	pthread_mutex_t		lock;
	pthread_rwlock_t	rwlock;
};
struct dlist_node_t {
	dlist_node_t		prev, next;
	void			*value;
};
struct dlist_iter_t {
	dlist_node_t		next;
	int			direction;
};

dlist_t dlist_new(int cmp(const void *x, const void *y), void vfree(void *value)) {
	dlist_t dlist;
	pthread_mutexattr_t mattr;
	pthread_rwlockattr_t rwattr;

	if (NEW(dlist) == NULL)
		return NULL;
	dlist->length = 0;
	dlist->head   = dlist->tail = NULL;
	dlist->cmp    = cmp;
	dlist->vfree  = vfree;
	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&dlist->lock, &mattr);
	pthread_mutexattr_destroy(&mattr);
	pthread_rwlockattr_init(&rwattr);
	pthread_rwlockattr_setkind_np(&rwattr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
	pthread_rwlock_init(&dlist->rwlock, &rwattr);
	pthread_rwlockattr_destroy(&rwattr);
	return dlist;
}

/* can't fail */
void dlist_free(dlist_t *dlp) {
	dlist_node_t curr, next;
	unsigned long len;

	if (dlp == NULL || *dlp == NULL)
		return;
	pthread_mutex_destroy(&(*dlp)->lock);
	pthread_rwlock_destroy(&(*dlp)->rwlock);
	curr = (*dlp)->head;
	len = (*dlp)->length;
	while (len--) {
		next = curr->next;
		if ((*dlp)->vfree)
			(*dlp)->vfree(curr->value);
		FREE(curr);
		curr = next;
	}
	FREE(*dlp);
}

unsigned long dlist_length(dlist_t dlist) {
	if (dlist == NULL)
		return 0;
	return dlist->length;
}

dlist_node_t dlist_head(dlist_t dlist) {
	if (dlist == NULL)
		return NULL;
	return dlist->head;
}

dlist_node_t dlist_tail(dlist_t dlist) {
	if (dlist == NULL)
		return NULL;
	return dlist->tail;
}

dlist_node_t dlist_node_prev(dlist_node_t node) {
	if (node == NULL)
		return NULL;
	return node->prev;
}

dlist_node_t dlist_node_next(dlist_node_t node) {
	if (node == NULL)
		return NULL;
	return node->next;
}

void *dlist_node_value(dlist_node_t node) {
	if (node == NULL)
		return NULL;
	return node->value;
}

dlist_iter_t dlist_iter_new(dlist_t dlist, int direction) {
	dlist_iter_t iter;

	if (dlist == NULL || NEW(iter) == NULL)
		return NULL;
	iter->next      = direction == DLIST_START_HEAD ? dlist->head : dlist->tail;
	iter->direction = direction;
	return iter;
}

void dlist_iter_free(dlist_iter_t *dlip) {
	if (dlip == NULL || *dlip == NULL)
		return;
	FREE(*dlip);
}

void dlist_iter_rewind_head(dlist_iter_t iter, dlist_t dlist) {
	if (iter == NULL || dlist == NULL)
		return;
	iter->next      = dlist->head;
	iter->direction = DLIST_START_HEAD;
}

void dlist_iter_rewind_tail(dlist_iter_t iter, dlist_t dlist) {
	if (iter == NULL || dlist == NULL)
		return;
	iter->next      = dlist->tail;
	iter->direction = DLIST_START_TAIL;
}

dlist_node_t dlist_next(dlist_iter_t iter) {
	dlist_node_t node;

	if (iter == NULL)
		return NULL;
	node = iter->next;
	if (node)
		iter->next = iter->direction == DLIST_START_HEAD ? node->next : node->prev;
	return node;
}

dlist_t dlist_insert_head(dlist_t dlist, void *value) {
	dlist_node_t node;

	if (dlist == NULL || NEW(node) == NULL)
		return NULL;
	node->value = value;
	if (dlist->head == NULL) {
		node->prev = node->next = NULL;
		dlist->head = dlist->tail = node;
	} else {
		node->prev = NULL;
		node->next = dlist->head;
		dlist->head->prev = node;
		dlist->head = node;
	}
	++dlist->length;
	return dlist;
}

dlist_t dlist_insert_tail(dlist_t dlist, void *value) {
	dlist_node_t node;

	if (dlist == NULL || NEW(node) == NULL)
		return NULL;
	node->value = value;
	if (dlist->head == NULL) {
		node->prev = node->next = NULL;
		dlist->head = dlist->tail = node;
	} else {
		node->prev = dlist->tail;
		node->next = NULL;
		dlist->tail->next = node;
		dlist->tail = node;
	}
	++dlist->length;
	return dlist;
}

dlist_t dlist_insert(dlist_t dlist, dlist_node_t node, void *value, int after) {
	dlist_node_t new_node;

	if (dlist == NULL || node == NULL || NEW(new_node) == NULL)
		return NULL;
	new_node->value = value;
	if (after) {
		new_node->prev = node;
		new_node->next = node->next;
		if (dlist->tail == node)
			dlist->tail = new_node;
	} else {
		new_node->prev = node->prev;
		new_node->next = node;
		if (dlist->head == node)
			dlist->head = new_node;
	}
	if (new_node->prev)
		new_node->prev->next = new_node;
	if (new_node->next)
		new_node->next->prev = new_node;
	++dlist->length;
	return dlist;
}

/* FIXME */
dlist_t dlist_insert_sort(dlist_t dlist, void *value) {
	if (dlist == NULL || dlist->cmp == NULL)
		return NULL;
	if (dlist->head == NULL) {
		dlist_node_t node;

		if (NEW(node) == NULL)
			return NULL;
		node->value = value;
		node->prev = node->next = NULL;
		dlist->head = dlist->tail = node;
		++dlist->length;
	} else {
		dlist_node_t curr, prev;

		for (curr = dlist->head, prev = NULL; curr; prev = curr, curr = curr->next)
			if (dlist->cmp(curr->value, value) > 0)
				break;
		if (prev == NULL)
			dlist_insert_head(dlist, value);
		else if (curr == NULL)
			dlist_insert_tail(dlist, value);
		else
			dlist_insert(dlist, prev, value, 1);
	}
	return dlist;
}

dlist_node_t dlist_find(dlist_t dlist, void *value) {
	dlist_iter_t iter;
	dlist_node_t node;

	if (dlist == NULL)
		return NULL;
	iter = dlist_iter_new(dlist, DLIST_START_HEAD);
	while ((node = dlist_next(iter)))
		if (dlist->cmp) {
			if (dlist->cmp(node->value, value) == 0)
				break;
		} else if (node->value == value)
			break;
	dlist_iter_free(&iter);
	return node;
}

dlist_node_t dlist_index(dlist_t dlist, long index) {
	dlist_node_t node;

	if (dlist == NULL)
		return NULL;
	if (index < 0) {
		index = (-index) - 1;
		node = dlist->tail;
		while (index-- && node)
			node = node->prev;
	} else {
		node = dlist->head;
		while (index-- && node)
			node = node->next;
	}
	return node;
}

void *dlist_remove_head(dlist_t dlist) {
	dlist_node_t node;
	void *value = NULL;

	if (dlist == NULL)
		return NULL;
	if ((node = dlist->head)) {
		dlist->head = node->next;
		if (dlist->tail == node)
			dlist->tail = NULL;
		else
			node->next->prev = NULL;
		value = node->value;
		FREE(node);
		--dlist->length;
	}
	return value;
}

void *dlist_remove_tail(dlist_t dlist) {
	dlist_node_t node;
	void *value = NULL;

	if (dlist == NULL)
		return NULL;
	if ((node = dlist->tail)) {
		dlist->tail = node->prev;
		if (dlist->head == node)
			dlist->head = NULL;
		else
			node->prev->next = NULL;
		value = node->value;
		FREE(node);
		--dlist->length;
	}
	return value;
}

void *dlist_remove(dlist_t dlist, dlist_node_t node) {
	void *value;

	if (dlist == NULL || node == NULL)
		return NULL;
	if (node->prev)
		node->prev->next = node->next;
	else
		dlist->head = node->next;
	if (node->next)
		node->next->prev = node->prev;
	else
		dlist->tail = node->prev;
	value = node->value;
	FREE(node);
	--dlist->length;
	return value;
}

dlist_t dlist_append(dlist_t dlist, dlist_t tail) {
	if (dlist == NULL || tail == NULL)
		return NULL;
	if (tail->head == NULL)
		return dlist;
	if (dlist->head == NULL) {
		dlist->head = tail->head;
		dlist->tail = tail->tail;
	} else {
		dlist->tail->next = tail->head;
		tail->head->prev = dlist->tail;
		dlist->tail = tail->tail;
	}
	dlist->length += tail->length;
	/* FIXME */
	tail->length = 0;
	tail->head   = tail->tail = NULL;
	return dlist;
}

dlist_t dlist_copy(dlist_t dlist) {
	dlist_t copy;
	dlist_iter_t iter;
	dlist_node_t node;

	if (dlist == NULL || (copy = dlist_new(dlist->cmp, dlist->vfree)) == NULL)
		return NULL;
	iter = dlist_iter_new(dlist, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		void *value = node->value;

		if (dlist_insert_tail(dlist, value) == NULL) {
			dlist_iter_free(&iter);
			dlist_free(&copy);
			return NULL;
		}
	}
	dlist_iter_free(&iter);
	return copy;
}

void dlist_rotate(dlist_t dlist) {
	dlist_node_t node;

	if (dlist == NULL || dlist->length <= 1)
		return;
	node = dlist->tail;
	dlist->tail = node->prev;
	dlist->tail->next = NULL;
	node->prev = NULL;
	node->next = dlist->head;
	dlist->head->prev = node;
	dlist->head = node;
}

void dlist_lock(dlist_t dlist) {
	if (dlist == NULL)
		return;
	pthread_mutex_lock(&dlist->lock);
}

void dlist_unlock(dlist_t dlist) {
	if (dlist == NULL)
		return;
	pthread_mutex_unlock(&dlist->lock);
}

void dlist_rwlock_rdlock(dlist_t dlist) {
	if (dlist == NULL)
		return;
	pthread_rwlock_rdlock(&dlist->rwlock);
}

void dlist_rwlock_wrlock(dlist_t dlist) {
	if (dlist == NULL)
		return;
	pthread_rwlock_wrlock(&dlist->rwlock);
}

void dlist_rwlock_unlock(dlist_t dlist) {
	if (dlist == NULL)
		return;
	pthread_rwlock_unlock(&dlist->rwlock);
}

