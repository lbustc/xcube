/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tailored by xiaoyem
 */

#include "fmacros.h"
#include <errno.h>
#include <signal.h>
#include <time.h>
#include "mem.h"
#include "thrpool.h"

/* FIXME */
typedef struct job_t *job_t;
struct job_t {
	job_t		link;
	int		(*func)(void *arg, void *arg2);
	void		*arg;
	void		*arg2;
	void		(*afree)(void *arg);
	void		(*afree2)(void *arg2);
};
typedef struct active_t *active_t;
struct active_t {
	active_t	link;
	pthread_t	thread;
	int		(*func)(void *arg, void *arg2);
};
struct thrpool_t {
	int		min;
	int		max;
	int		curr;
	int		idle;
	int		linger;
	pthread_attr_t	attr;
	job_t		head, tail;
	active_t	active;
	/* THRPOOL_WAIT, THRPOOL_FREE */
	int		flags;
	pthread_mutex_t	lock;
	pthread_cond_t	busycond;
	pthread_cond_t	workcond;
	pthread_cond_t	waitcond;
	thrpool_t	prev, next;
};

#define THRPOOL_WAIT 1
#define THRPOOL_FREE 2

static thrpool_t thrpools = NULL;
static pthread_mutex_t thrpools_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static sigset_t fillset;

static int create_worker(thrpool_t tp);

static void clone_attr(pthread_attr_t *new, pthread_attr_t *old) {
	pthread_attr_init(new);
	/* FIXME */
	if (old) {
		void *addr;
		size_t size;
		int value;
		struct sched_param param;

		pthread_attr_getstack(old, &addr, &size);
		pthread_attr_setstack(new, NULL, size);
		pthread_attr_getscope(old, &value);
		pthread_attr_setscope(new, value);
		pthread_attr_getinheritsched(old, &value);
		pthread_attr_setinheritsched(new, value);
		pthread_attr_getschedpolicy(old, &value);
		pthread_attr_setschedpolicy(new, value);
		pthread_attr_getschedparam(old, &param);
		pthread_attr_setschedparam(new, &param);
		pthread_attr_getguardsize(old, &size);
		pthread_attr_setguardsize(new, size);
	}
	pthread_attr_setdetachstate(new, PTHREAD_CREATE_DETACHED);
}

static void cleanup_worker(void *arg) {
	thrpool_t tp = (thrpool_t)arg;

	--tp->curr;
	if (tp->flags & THRPOOL_FREE) {
		if (tp->curr == 0)
			pthread_cond_broadcast(&tp->busycond);
	/* FIXME */
	} else if (tp->head && tp->curr < tp->max && create_worker(tp) == 0)
		++tp->curr;
	pthread_mutex_unlock(&tp->lock);
}

static void notify_waiters(thrpool_t tp) {
	if (tp->head == NULL && tp->active == NULL) {
		tp->flags &= ~THRPOOL_WAIT;
		pthread_cond_broadcast(&tp->waitcond);
	}
}

static void cleanup_job(void *arg) {
	thrpool_t tp = (thrpool_t)arg;
	pthread_t mytid = pthread_self();
	active_t p, *pp;

	pthread_mutex_lock(&tp->lock);
	for (pp = &tp->active; (p = *pp); pp = &p->link)
		if (p->thread == mytid) {
			*pp = p->link;
			break;
		}
	if (tp->flags & THRPOOL_WAIT)
		notify_waiters(tp);
}

static void *worker_thread(void *arg) {
	thrpool_t tp = (thrpool_t)arg;
	/* FIXME */
	struct active_t active;

	pthread_mutex_lock(&tp->lock);
	pthread_cleanup_push(cleanup_worker, tp);
	for (;;) {
		int timedout;
		job_t job;

		/* reset signal mask and cancellation state */
		pthread_sigmask(SIG_SETMASK, &fillset, NULL);
		pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		timedout = 0;
		++tp->idle;
		if (tp->flags & THRPOOL_WAIT)
			notify_waiters(tp);
		while (tp->head == NULL && !(tp->flags & THRPOOL_FREE))
			if (tp->curr <= tp->min)
				pthread_cond_wait(&tp->workcond, &tp->lock);
			else {
				struct timespec ts;

				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_sec += tp->linger;
				if (tp->linger == 0 ||
					pthread_cond_timedwait(&tp->workcond, &tp->lock, &ts) == ETIMEDOUT) {
					timedout = 1;
					break;
				}
			}
		--tp->idle;
		if (tp->flags & THRPOOL_FREE)
			break;
		if ((job = tp->head)) {
			timedout = 0;
			tp->head = job->link;
			if (job == tp->tail)
				tp->tail = NULL;
			/* FIXME */
			active.link   = tp->active;
			active.thread = pthread_self();
			active.func   = job->func;
			tp->active = &active;
			pthread_mutex_unlock(&tp->lock);
			pthread_cleanup_push(cleanup_job, tp);
			/* If the job function calls pthread_exit(),
			 * the thread calls cleanup_job(tp) and cleanup_worker(tp). */
			job->func(job->arg, job->arg2);
			FREE(job);
			/* cleanup_job(tp) */
			pthread_cleanup_pop(1);
		}
		if (timedout && tp->curr > tp->min)
			break;
	}
	/* cleanup_worker(tp) */
	pthread_cleanup_pop(1);
	return NULL;
}

static int create_worker(thrpool_t tp) {
	sigset_t oldset;
	/* FIXME */
	pthread_t thread;
	int error;

	pthread_sigmask(SIG_SETMASK, &fillset, &oldset);
	error = pthread_create(&thread, &tp->attr, worker_thread, tp);
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	return error;
}

thrpool_t thrpool_new(int min, int max, int linger, pthread_attr_t *attr) {
	thrpool_t tp;
	pthread_mutexattr_t ma;

	if (min > max || max < 1)
		return NULL;
	if (NEW0(tp) == NULL)
		return NULL;
	sigfillset(&fillset);
	tp->min    = min;
	tp->max    = max;
	tp->curr   = 0;
	tp->idle   = 0;
	tp->linger = linger;
	clone_attr(&tp->attr, attr);
	tp->flags  = 0;
	pthread_mutexattr_init(&ma);
	pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&tp->lock, &ma);
	pthread_mutexattr_destroy(&ma);
	pthread_cond_init(&tp->busycond, NULL);
	pthread_cond_init(&tp->workcond, NULL);
	pthread_cond_init(&tp->waitcond, NULL);
	pthread_mutex_lock(&thrpools_lock);
	if (thrpools == NULL) {
		tp->prev = tp;
		tp->next = tp;
		thrpools = tp;
	} else {
		thrpools->prev->next = tp;
		tp->prev = thrpools->prev;
		tp->next = thrpools;
		thrpools->prev = tp;
	}
	pthread_mutex_unlock(&thrpools_lock);
	return tp;
}

void thrpool_free(thrpool_t *tpp) {
	active_t p;
	job_t job;

	pthread_mutex_lock(&(*tpp)->lock);
	(*tpp)->flags |= THRPOOL_FREE;
	/* wake up idle workers */
	pthread_cond_broadcast(&(*tpp)->workcond);
	/* cancel active workers */
	for (p = (*tpp)->active; p; p = p->link)
		pthread_cancel(p->thread);
	/* wait for active workers to finish */
	while ((*tpp)->active) {
		(*tpp)->flags |= THRPOOL_WAIT;
		pthread_cond_wait(&(*tpp)->waitcond, &(*tpp)->lock);
	}
	while ((*tpp)->curr != 0)
		pthread_cond_wait(&(*tpp)->busycond, &(*tpp)->lock);
	pthread_mutex_unlock(&(*tpp)->lock);
	pthread_mutex_lock(&thrpools_lock);
	if (thrpools == *tpp)
		thrpools = (*tpp)->next;
	if (thrpools == *tpp)
		thrpools = NULL;
	else {
		(*tpp)->prev->next = (*tpp)->next;
		(*tpp)->next->prev = (*tpp)->prev;
	}
	pthread_mutex_unlock(&thrpools_lock);
	/* There should be no pending jobs, but just in case ... */
	for (job = (*tpp)->head; job; job = (*tpp)->head) {
		(*tpp)->head = job->link;
		FREE(job);
	}
	pthread_attr_destroy(&(*tpp)->attr);
	FREE(*tpp);
}

int thrpool_queue(thrpool_t tp, int func(void *arg, void *arg2), void *arg, void *arg2,
	void afree(void *arg), void afree2(void *arg2)) {
	job_t job;

	if (NEW(job) == NULL)
		return -1;
	job->link   = NULL;
	job->func   = func;
	job->arg    = arg;
	job->arg2   = arg2;
	job->afree  = afree;
	job->afree2 = afree2;
	pthread_mutex_lock(&tp->lock);
	if (tp->head == NULL)
		tp->head = job;
	else
		tp->tail->link = job;
	tp->tail = job;
	if (tp->idle > 0)
		pthread_cond_signal(&tp->workcond);
	/* FIXME */
	else if (tp->curr < tp->max && create_worker(tp) == 0)
		++tp->curr;
	pthread_mutex_unlock(&tp->lock);
	return 0;
}

void thrpool_remove(thrpool_t tp, int func(void *, void *)) {
	job_t job, prev, curr, next;
	active_t p;

	pthread_mutex_lock(&tp->lock);
	for (job = tp->head, prev = NULL, curr = job, next = job ? job->link : NULL; job;
		prev = curr, job = next, curr = job, next = job ? job->link : NULL)
		if (job->func == func) {
			curr = prev;
			if (prev == NULL)
				tp->head = next;
			else
				prev->link = next;
			if (next == NULL)
				tp->tail = prev;
			if (job->afree)
				job->afree(job->arg);
			if (job->afree2)
				job->afree2(job->arg2);
			FREE(job);
		}
	/* FIXME */
	for (;;) {
		int running = 0;

		for (p = tp->active; p; p = p->link)
			if (p->func == func) {
				running = 1;
				break;
			}
		if (running) {
			tp->flags |= THRPOOL_WAIT;
			pthread_cond_wait(&tp->waitcond, &tp->lock);
		} else
			break;
	}
	pthread_mutex_unlock(&tp->lock);
}

void thrpool_wait(thrpool_t tp) {
	pthread_mutex_lock(&tp->lock);
	while (tp->head && tp->active) {
		tp->flags |= THRPOOL_WAIT;
		pthread_cond_wait(&tp->waitcond, &tp->lock);
	}
	pthread_mutex_unlock(&tp->lock);
}

