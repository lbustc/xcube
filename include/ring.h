/*
 * Copyright (c) 1994,1995,1996,1997 by David R. Hanson.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * <http://www.opensource.org/licenses/mit-license.php>
 */

#ifndef RING_INCLUDED
#define RING_INCLUDED

#include <stddef.h>

/* exported types */
typedef struct ring_t *ring_t;

/* exported functions */
extern ring_t ring_new(void);
extern ring_t ring_ring(void *x, ...);
extern void   ring_free(ring_t *ring);
extern size_t ring_length(ring_t ring);
extern void  *ring_put(ring_t ring, int i, void *x);
extern void  *ring_get(ring_t ring, int i);
extern void  *ring_add(ring_t ring, int pos, void *x);
extern void  *ring_addlo(ring_t ring, void *x);
extern void  *ring_addhi(ring_t ring, void *x);
extern void  *ring_remove(ring_t ring, int i);
extern void  *ring_remlo(ring_t ring);
extern void  *ring_remhi(ring_t ring);
extern void   ring_rotate(ring_t ring, int n);

#endif /* RING_INCLUDED */

