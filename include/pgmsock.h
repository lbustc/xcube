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

#ifndef PGMSOCK_INCLUDED
#define PGMSOCK_INCLUDED

#include <pgm/pgm.h>

#define PGMSOCK_SENDER   0
#define PGMSOCK_RECEIVER 1

/* FIXME: exported functions */
extern pgm_sock_t *pgmsock_create(const char *network, int port, int type);
extern void        pgmsock_destroy(pgm_sock_t *pgmsock);

#endif /* PGMSOCK_INCLUDED */

