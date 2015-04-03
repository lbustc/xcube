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

#ifndef EVENT_INCLUDED
#define EVENT_INCLUDED

#define EVENT_NONE     0
#define EVENT_READABLE 1
#define EVENT_WRITABLE 2
#define EVENT_NOMORE  -1

#define FILE_EVENTS    1
#define TIME_EVENTS    2
#define ALL_EVENTS     (FILE_EVENTS | TIME_EVENTS)
#define DONT_WAIT      4

/* exported types */
typedef struct file_event *file_event;
typedef struct time_event *time_event;
typedef struct event_loop *event_loop;
typedef void file_proc(event_loop el, int fd, int mask, void *data);
typedef int  time_proc(event_loop el, long long id, void *data);
typedef void finalizer(event_loop el, void *data);

/* FIXME: exported functions */
extern event_loop create_event_loop(int size);
extern event_loop create_event_loop_safe(int size);
extern void       delete_event_loop(event_loop el);
extern int        create_file_event(event_loop el, int fd, int mask, file_proc *proc, void *data);
extern void       delete_file_event(event_loop el, int fd, int mask);
extern long long  create_time_event(event_loop el, long long ms,
			time_proc *proc, finalizer *f, void *data);
extern int        delete_time_event(event_loop el, long long id);
extern int        process_events(event_loop el, int flags);
extern void       start_event_loop(event_loop el, int flags);
extern void       stop_event_loop(event_loop el);

#endif /* EVENT_INCLUDED */

