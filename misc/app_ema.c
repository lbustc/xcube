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

#include "fmacros.h"
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include "macros.h"
#include "mem.h"
#include "stl.h"
#include "logger.h"
#include "config.h"
#include "module.h"
#include "basics.h"

static char *app = "ema";
static char *desc = "Exponential Moving Average";
static char *fmt = "EMA,timestamp,contract,ema";
static map_t *contracts;
static pthread_mutex_t conlock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static struct config *cfg;
static int n = 20;

static void load_config(void) {
	/* FIXME */
	if ((cfg = config_load("/etc/xcb/ema.conf"))) {
		char *cat = category_browse(cfg, NULL);

		while (cat ) {
			if (!strcasecmp(cat, "general")) {
				struct variable *var = variable_browse(cfg, cat);

				while (var) {
					if (!strcasecmp(var->name, "number")) {
						if (strcasecmp(var->value, ""))
							n = atoi(var->value);
					} else
						xcb_log(XCB_LOG_WARNING, "Unknown variable '%s' in "
							"category '%s' of ema.conf", var->name, cat);
					var = var->next;
				}
			}
			cat = category_browse(cfg, cat);
		}
	}
}

static int ema_exec(void *data, void *data2) {
	RAII_VAR(struct msg *, msg, (struct msg *)data, msg_decr);
	Quote *quote = (Quote *)msg->data;
	float *price;
	map_iter_t *iter = map_iter_create();
	deq_t *prices;
	int size;
	NOT_USED(data2);

	/* FIXME */
	if (fabs(quote->thyquote.m_dZXJ) <= 0.000001) {
		xcb_log(XCB_LOG_WARNING, "Invalid quote: '%d,%d,%s,%.2f'",
			quote->thyquote.m_nTime,
			quote->m_nMSec,
			quote->thyquote.m_cHYDM,
			quote->thyquote.m_dZXJ);
		goto end;
	}
	if ((price = ALLOC(sizeof (float))) == NULL) {
		xcb_log(XCB_LOG_WARNING, "Error allocating memory for price");
		goto end;
	}
	*price = quote->thyquote.m_dZXJ;
	pthread_mutex_lock(&conlock);
	map_find(iter, contracts, quote->thyquote.m_cHYDM);
	if (!map_iter_valid(iter, contracts)) {
		const char *contract;

		if ((contract = mem_strdup(quote->thyquote.m_cHYDM)) == NULL) {
			xcb_log(XCB_LOG_WARNING, "Error allocating memory for contract");
			pthread_mutex_unlock(&conlock);
			FREE(price);
			goto end;
		}
		prices = deq_create();
		map_insert(contracts, contract, prices);
	} else
		prices = map_iter_value(iter);
	deq_push_back(prices, price);
	if ((size = deq_size(prices)) == n) {
		int i;
		float sum = *((float *)deq_at(prices, 0));
		time_t t = (time_t)quote->thyquote.m_nTime;
		struct tm lt;
		char datestr[64], res[256];
		float *front;

		for (i = 1; i < size; ++i)
			sum = (2.0 / (n + 1)) * *((float *)deq_at(prices, i)) + (1 - (2.0 / (n + 1))) * sum;
		strftime(datestr, sizeof datestr, "%F %T", localtime_r(&t, &lt));
		snprintf(res, sizeof res, "EMA,%s.%03d,%s,%.2f",
			datestr,
			quote->m_nMSec,
			quote->thyquote.m_cHYDM,
			sum / n);
		out2rmp(res);
		front = deq_front(prices);
		FREE(front);
		deq_pop_front(prices);
	}
	pthread_mutex_unlock(&conlock);
	map_iter_destroy(iter);

end:
	return 0;
}

static void free_prices(map_t *contracts) {
	map_iter_t *iter = map_iter_create();

	for (map_begin(iter, contracts); map_iter_valid(iter, contracts); map_iter_next(iter)) {
		void *contract = (void *)map_iter_key(iter);
		deq_t *prices = map_iter_value(iter);
		int i, size = deq_size(prices);

		FREE(contract);
		for (i = 0; i < size; ++i) {
			float *price = deq_at(prices, i);

			FREE(price);
		}
		deq_destroy(prices);
	}
	map_iter_destroy(iter);
}

static int load_module(void) {
	load_config();
	contracts = map_create();
	if (msgs_hook(&default_msgs, ema_exec, NULL) == -1)
		return MODULE_LOAD_FAILURE;
	return register_application(app, ema_exec, desc, fmt, mod_info->self);
}

static int unload_module(void) {
	msgs_unhook(&default_msgs, ema_exec);
	free_prices(contracts);
	map_destroy(contracts);
	return unregister_application(app);
}

static int reload_module(void) {
	msgs_unhook(&default_msgs, ema_exec);
	free_prices(contracts);
	map_clear(contracts);
	load_config();
	if (msgs_hook(&default_msgs, ema_exec, NULL) == -1)
		return MODULE_LOAD_FAILURE;
	return MODULE_LOAD_SUCCESS;
}

MODULE_INFO(load_module, unload_module, reload_module, "Exponential Moving Average Application");

