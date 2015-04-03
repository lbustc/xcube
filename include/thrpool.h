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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tailored by xiaoyem
 */

#ifndef THRPOOL_INCLUDED
#define THRPOOL_INCLUDED

#include <pthread.h>

/* exported types */
typedef struct thrpool_t *thrpool_t;

/* FIXME: exported functions */
extern thrpool_t thrpool_new(int min, int max, int linger, pthread_attr_t *attr);
extern void      thrpool_free(thrpool_t *tpp);
extern int       thrpool_queue(thrpool_t tp, int func(void *arg, void *arg2), void *arg, void *arg2,
			void afree(void *arg), void afree2(void *arg2));
extern void      thrpool_remove(thrpool_t tp, int func(void *arg, void *arg2));
extern void      thrpool_wait(thrpool_t tp);

#endif /* THRPOOL_INCLUDED */

