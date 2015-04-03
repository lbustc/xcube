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

#include <string.h>
#include "macros.h"
#include "mem.h"
#include "dstr.h"
#include "module.h"
#include "basics.h"

static char *app = "test";
static char *desc = "Communication Tester";

/* reverse a string */
static int test_exec(void *data, void *data2) {
	RAII_VAR(struct msg *, msg, (struct msg *)data, msg_decr);
	char *str = (char *)msg->data;
	dstr res;
	NOT_USED(data2);

	if (str) {
		char *end = str + strlen(str) - 1;

#define XOR_SWAP(a, b) \
	do { \
		a ^= b; \
		b ^= a; \
		a ^= b; \
	} while (0)
		while (str < end) {
			XOR_SWAP(*str, *end);
			++str;
			--end;
		}
#undef XOR_SWAP
	}
	/* FIXME */
	if ((res = dstr_new("TEST,")))
		if ((res = dstr_cat(res, msg->data)))
			out2rmp(res);
	dstr_free(res);
	return 0;
}

static int load_module(void) {
	return register_application(app, test_exec, desc, NULL, mod_info->self);
}

static int unload_module(void) {
	return unregister_application(app);
}

static int reload_module(void) {
	/* do nothing */
	return MODULE_LOAD_SUCCESS;
}

MODULE_INFO(load_module, unload_module, reload_module, "Communication Test Application");

