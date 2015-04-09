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

#include "fmacros.h"
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "macros.h"
#include "mem.h"
#include "table.h"
#include "dstr.h"
#include "logger.h"
#include "config.h"
#include "event.h"
#include "module.h"
#include "utilities.h"
#include "basics.h"

/* FIXME */
struct ohlc {
	int			time, ms;
	char			*contract;
	float			prehigh, prelow, open, high, low, close;
	int			prevolume, preopenint, volume, openint;
	unsigned long		id;
	pthread_spinlock_t	lock;
};

/* FIXME */
static char *app = "kline";
static char *desc = "Kline, or Candlestick";
static char *fmt = "KLINE,timestamp,contract,open,high,low,close,volume,openint";
static table_t contracts;
static event_loop el;
static pthread_t thread;
static struct config *cfg;
static int s = 60;

static inline void load_config(void) {
	/* FIXME */
	if ((cfg = config_load("/etc/xcb/kline.conf"))) {
		char *cat = category_browse(cfg, NULL);

		while (cat) {
			if (!strcasecmp(cat, "general")) {
				struct variable *var = variable_browse(cfg, cat);

				while (var) {
					if (!strcasecmp(var->name, "seconds")) {
						if (strcasecmp(var->value, ""))
							s = atoi(var->value);
					} else
						xcb_log(XCB_LOG_WARNING, "Unknown variable '%s' in "
							"category '%s' of kline.conf", var->name, cat);
					var = var->next;
				}
			}
			cat = category_browse(cfg, cat);
		}
	}
}

static int kline_output(event_loop el, unsigned long id, void *data) {
	struct ohlc *ohlc = (struct ohlc *)data;
	time_t t;
	struct tm lt;
	char datestr[64], res[512];
	NOT_USED(el);
	NOT_USED(id);

	pthread_spin_lock(&ohlc->lock);
	ohlc->id = -1;
	t = (time_t)ohlc->time;
	strftime(datestr, sizeof datestr, "%F %T", localtime_r(&t, &lt));
	snprintf(res, sizeof res, "KLINE,%s.000,%s|%.2f,%.2f,%.2f,%.2f,%d,%d",
		datestr,
		ohlc->contract,
		ohlc->open,
		ohlc->high,
		ohlc->low,
		ohlc->close,
		ohlc->volume - ohlc->prevolume,
		ohlc->openint);
	pthread_spin_unlock(&ohlc->lock);
	out2rmp(res);
	return EVENT_NOMORE;
}

static int kline_exec(void *data, void *data2) {
	RAII_VAR(struct msg *, msg, (struct msg *)data, msg_decr);
	Quote *quote = (Quote *)msg->data;
	dstr contract;
	struct ohlc *ohlc;
	NOT_USED(data2);

	contract = dstr_new(quote->thyquote.m_cHYDM);
	/* FIXME */
	if (!strcasecmp(contract, "") || fabs(quote->thyquote.m_dZXJ) <= 0.000001) {
		xcb_log(XCB_LOG_WARNING, "Invalid quote: '%d,%d,%s,%.2f,%.2f,%.2f,%d,%d'",
			quote->thyquote.m_nTime,
			quote->m_nMSec,
			contract,
			quote->thyquote.m_dZXJ,
			quote->thyquote.m_dZGJ,
			quote->thyquote.m_dZDJ,
			quote->thyquote.m_nCJSL,
			quote->thyquote.m_nCCL);
		dstr_free(contract);
		goto end;
	}
	table_lock(contracts);
	if ((ohlc = table_get_value(contracts, contract)) == NULL) {
		if (NEW(ohlc) == NULL) {
			xcb_log(XCB_LOG_WARNING, "Error allocating memory for ohlc");
			table_unlock(contracts);
			goto end;
		}
		ohlc->time       = quote->thyquote.m_nTime;
		ohlc->time      -= ohlc->time % s;
		ohlc->ms         = quote->m_nMSec;
		ohlc->contract   = contract;
		ohlc->prehigh    = quote->thyquote.m_dZGJ;
		ohlc->prelow     = quote->thyquote.m_dZDJ;
		ohlc->open       = quote->thyquote.m_dZXJ;
		ohlc->high       = quote->thyquote.m_dZXJ;
		ohlc->low        = quote->thyquote.m_dZXJ;
		ohlc->close      = quote->thyquote.m_dZXJ;
		ohlc->prevolume  = 0;
		ohlc->preopenint = 0;
		ohlc->volume     = quote->thyquote.m_nCJSL;
		ohlc->openint    = quote->thyquote.m_nCCL;
		ohlc->id         = create_time_event(el, (s - quote->thyquote.m_nTime % s) * 1000 - ohlc->ms,
					kline_output, NULL, ohlc);
		pthread_spin_init(&ohlc->lock, 0);
		table_insert(contracts, contract, ohlc);
	} else {
		int time = quote->thyquote.m_nTime;

		time -= time % s;
		pthread_spin_lock(&ohlc->lock);
		if (time == ohlc->time) {
			if (ohlc->open < 0.0) {
				/* only if volume or open interest has changed */
				if (quote->thyquote.m_nCJSL != ohlc->prevolume ||
					quote->thyquote.m_nCCL != ohlc->preopenint) {
					ohlc->ms      = quote->m_nMSec;
					ohlc->prehigh = quote->thyquote.m_dZGJ;
					ohlc->prelow  = quote->thyquote.m_dZDJ;
					ohlc->open    = quote->thyquote.m_dZXJ;
					ohlc->high    = quote->thyquote.m_dZXJ;
					ohlc->low     = quote->thyquote.m_dZXJ;
					ohlc->close   = quote->thyquote.m_dZXJ;
					ohlc->volume  = quote->thyquote.m_nCJSL;
					ohlc->openint = quote->thyquote.m_nCCL;
					ohlc->id      = create_time_event(el,
							(s - quote->thyquote.m_nTime % s) * 1000 - ohlc->ms,
							kline_output, NULL, ohlc);
				}
			} else {
				if (ohlc->high < quote->thyquote.m_dZXJ)
					ohlc->high = quote->thyquote.m_dZXJ;
				if (fabs(quote->thyquote.m_dZGJ - ohlc->prehigh) > 0.000001 &&
					ohlc->high < MAX(quote->thyquote.m_dZGJ, quote->thyquote.m_dZXJ))
					ohlc->high = MAX(quote->thyquote.m_dZGJ, quote->thyquote.m_dZXJ);
				ohlc->prehigh = quote->thyquote.m_dZGJ;
				if (ohlc->low > quote->thyquote.m_dZXJ)
					ohlc->low = quote->thyquote.m_dZXJ;
				if (fabs(quote->thyquote.m_dZDJ - ohlc->prelow) > 0.000001 &&
					ohlc->low > MIN(quote->thyquote.m_dZDJ, quote->thyquote.m_dZXJ))
					ohlc->low = MIN(quote->thyquote.m_dZDJ, quote->thyquote.m_dZXJ);
				ohlc->prelow  = quote->thyquote.m_dZDJ;
				ohlc->close   = quote->thyquote.m_dZXJ;
				ohlc->volume  = quote->thyquote.m_nCJSL;
				ohlc->openint = quote->thyquote.m_nCCL;
			}
		} else {
			if (ohlc->id > 0) {
				time_t t = (time_t)ohlc->time;
				struct tm lt;
				char datestr[64], res[512];

				xcb_log(XCB_LOG_INFO, "Deleting untriggered time event '%d'", ohlc->id);
				delete_time_event(el, ohlc->id);
				strftime(datestr, sizeof datestr, "%F %T", localtime_r(&t, &lt));
				snprintf(res, sizeof res, "KLINE,%s.000,%s|%.2f,%.2f,%.2f,%.2f,%d,%d",
					datestr,
					ohlc->contract,
					ohlc->open,
					ohlc->high,
					ohlc->low,
					ohlc->close,
					ohlc->volume - ohlc->prevolume,
					ohlc->openint);
				out2rmp(res);
			}
			/* Reset */
			ohlc->time       = time;
			ohlc->prehigh    = -1.0;
			ohlc->prelow     = -1.0;
			ohlc->open       = -1.0;
			ohlc->high       = -1.0;
			ohlc->low        = -1.0;
			ohlc->close      = -1.0;
			ohlc->prevolume  = ohlc->volume;
			ohlc->preopenint = ohlc->openint;
			ohlc->volume     = -1;
			ohlc->openint    = -1;
			ohlc->id         = -1;
			/* only if volume or open interest has changed */
			if (quote->thyquote.m_nCJSL != ohlc->prevolume ||
				quote->thyquote.m_nCCL != ohlc->preopenint) {
				ohlc->ms      = quote->m_nMSec;
				ohlc->prehigh = quote->thyquote.m_dZGJ;
				ohlc->prelow  = quote->thyquote.m_dZDJ;
				ohlc->open    = quote->thyquote.m_dZXJ;
				ohlc->high    = quote->thyquote.m_dZXJ;
				ohlc->low     = quote->thyquote.m_dZXJ;
				ohlc->close   = quote->thyquote.m_dZXJ;
				ohlc->volume  = quote->thyquote.m_nCJSL;
				ohlc->openint = quote->thyquote.m_nCCL;
				ohlc->id      = create_time_event(el,
						(s - quote->thyquote.m_nTime % s) * 1000 - ohlc->ms,
						kline_output, NULL, ohlc);
			}
		}
		pthread_spin_unlock(&ohlc->lock);
		dstr_free(contract);
	}
	table_unlock(contracts);

end:
	return 0;
}

static void kfree(const void *key) {
	dstr_free((dstr)key);
}

static void vfree(void *value) {
	struct ohlc *ohlc = (struct ohlc *)value;

	if (ohlc->id != -1) {
		xcb_log(XCB_LOG_INFO, "Deleting pending time event '%d'", ohlc->id);
		delete_time_event(el, ohlc->id);
	}
	pthread_spin_destroy(&ohlc->lock);
	FREE(ohlc);
}

static void *el_thread(void *data) {
	NOT_USED(data);

	start_event_loop(el, TIME_EVENTS);
	return NULL;
}

static int load_module(void) {
	load_config();
	contracts = table_new(cmpstr, hashmurmur2, kfree, vfree);
	if ((el = create_event_loop_safe(1)) == NULL)
		return MODULE_LOAD_FAILURE;
	if (pthread_create(&thread, NULL, el_thread, NULL) != 0)
		return MODULE_LOAD_FAILURE;
	if (msgs_hook(&default_msgs, kline_exec, NULL) == -1)
		return MODULE_LOAD_FAILURE;
	return register_application(app, kline_exec, desc, fmt, mod_info->self);
}

static int unload_module(void) {
	msgs_unhook(&default_msgs, kline_exec);
	stop_event_loop(el);
	pthread_cancel(thread);
	pthread_join(thread, NULL);
	table_free(&contracts);
	delete_event_loop(el);
	config_destroy(cfg);
	return unregister_application(app);
}

static int reload_module(void) {
	msgs_unhook(&default_msgs, kline_exec);
	stop_event_loop(el);
	pthread_cancel(thread);
	pthread_join(thread, NULL);
	table_clear(contracts);
	config_destroy(cfg);
	load_config();
	if (pthread_create(&thread, NULL, el_thread, NULL) != 0)
		return MODULE_LOAD_FAILURE;
	if (msgs_hook(&default_msgs, kline_exec, NULL) == -1)
		return MODULE_LOAD_FAILURE;
	return MODULE_LOAD_SUCCESS;
}

MODULE_INFO(load_module, unload_module, reload_module, "Kline Application");

