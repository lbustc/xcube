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

#ifndef BASICS_INCLUDED
#define BASICS_INCLUDED

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include "module.h"

/* long -> int32_t */
#pragma pack(push, 1)
typedef struct tagHYQuote {
	int32_t		m_nLen;		/* length */
	unsigned char	m_nVer;		/* version */
	int32_t		m_nTime;	/* update time */
	char		m_cJYS[3];	/* exchange */
	char		m_cHYDM[30];	/* instrument */
	bool		m_bTPBZ;	/* FIXME */
	float		m_dZJSJ;	/* pre settlement price */
	float		m_dJJSJ;	/* settlement price */
	float		m_dCJJJ;	/* average price */
	float		m_dZSP;		/* pre close price */
	float		m_dJSP;		/* close price */
	float		m_dJKP;		/* open price */
	int32_t		m_nZCCL;	/* pre open interest */
	int32_t		m_nCCL;		/* open interest */
	float		m_dZXJ;		/* last price */
	int32_t		m_nCJSL;	/* volume */
	double		m_dCJJE;	/* turnover */
	float		m_dZGBJ;	/* upper limit price */
	float		m_dZDBJ;	/* lower limit price */
	float		m_dZGJ;		/* highest price */
	float		m_dZDJ;		/* lowest price */
	float		m_dZXSD;	/* pre delta */
	float		m_dJXSD;	/* delta */
	float		m_dMRJG1;	/* bid price 1 */
	float		m_dMCJG1;	/* ask price 1 */
	int32_t		m_nMRSL1;	/* bid volume 1 */
	int32_t		m_nMCSL1;	/* ask volume 2 */
	float		m_dMRJG2;
	float		m_dMCJG2;
	int32_t		m_nMRSL2;
	int32_t		m_nMCSL2;
	float		m_dMRJG3;
	float		m_dMCJG3;
	int32_t		m_nMRSL3;
	int32_t		m_nMCSL3;
	float		m_dMRJG4;
	float		m_dMCJG4;
	int32_t		m_nMRSL4;
	int32_t		m_nMCSL4;
	float		m_dMRJG5;
	float		m_dMCJG5;
	int32_t		m_nMRSL5;
	int32_t		m_nMCSL5;
} THYQuote;
#pragma pack(pop)
typedef struct Quote {
	THYQuote	thyquote;
	int32_t		m_nMSec;
} Quote;

/* FIXME */
struct msg {
	struct msg	*link;
	void		*data;
	int		refcount;
};

/* FIXME */
#define FREEMSG(msg) \
	do { \
		if (msg) { \
			FREE(msg->data); \
			FREE(msg); \
		} \
	} while (0);

/* FIXME */
#define RAII_VAR(vartype, varname, initval, dtor) \
	auto void _dtor_ ## varname (vartype *v); \
	void _dtor_ ## varname (vartype *v) { dtor(*v); } \
	vartype varname __attribute__((cleanup(_dtor_ ## varname))) = initval

/* default queue */
extern struct msgs default_msgs;

/* FIXME */
extern void msg_ref(struct msg *msg, int delta);
extern void msg_incr(struct msg *msg);
extern void msg_decr(struct msg *msg);

/* init a queue */
extern int  msgs_init(struct msgs **msgs, const char *name, struct module *mod);
/* free a queue */
extern void msgs_free(struct msgs *msgs);
/* hook a function onto a queue */
extern int  msgs_hook(struct msgs *msgs, int (*exec)(void *data, void *data2), struct msgs *out);
/* hook a function onto a queue by name */
extern int  msgs_hook_name(const char *msgs, int(*exec)(void *data, void *data2), struct msgs *out);
/* unhook a function from a queue */
extern void msgs_unhook(struct msgs *msgs, int (*exec)(void *data, void *data2));
/* unhook a function from a queue by name */
extern void msgs_unhook_name(const char *msgs, int (*exec)(void *data, void *data2));
/* start a queue */
extern int  start_msgs(struct msgs *msgs);
/* stop a queue */
extern void stop_msgs(struct msgs *msgs);
/* check if a queue is used by other modules */
extern int  check_msgs(struct msgs *msgs);
/* output to rmp */
extern void out2rmp(const char *res);
/* output to another queue */
extern int  out2msgs(char *res, struct msgs *msgs);

#endif /* BASICS_INCLUDED */

