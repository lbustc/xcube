/*
 * Copyright (c) 2013-2015, Dalian Futures Information Technology Co., Ltd.
 *
 * Xiaoye Meng <mengxiaoye at dce dot com dot cn>
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

#include "mem.h"
#include "logger.h"
#include "basics.h"

/* FIXME */
void msg_ref(struct msg *msg, int delta) {
	int ret, val;

	if (msg == NULL || delta == 0)
		return;
	ret = __sync_fetch_and_add(&msg->refcount, delta);
	val = ret + delta;
	if (val > 0)
		return;
	if (val < 0) {
		xcb_log(XCB_LOG_WARNING, "Invalid refcount %d on msg '%p'", val, msg);
		return;
	}
	FREEMSG(msg);
}

/* FIXME */
inline void msg_incr(struct msg *msg) {
	msg_ref(msg, 1);
}

/* FIXME */
inline void msg_decr(struct msg *msg) {
	msg_ref(msg, -1);
}

