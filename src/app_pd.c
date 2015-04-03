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
#include <strings.h>
#include <time.h>
#include "macros.h"
#include "mem.h"
#include "dlist.h"
#include "table.h"
#include "logger.h"
#include "config.h"
#include "module.h"
#include "utilities.h"
#include "basics.h"

/* FIXME */
struct cpl {
	const char		*contract1, *contract2;
	float			price1, price2, prevpd;
	pthread_spinlock_t	lock;
};

/* FIXME */
static char *app = "pd";
static char *desc = "Price Difference";
static char *fmt = "PD,timestamp,contract1,contract2,lastprice1,lastprice2,pricediff";
static table_t contracts;
static dlist_t pairs;
static struct config *cfg;

static inline void load_config(void) {
	/* FIXME */
	if ((cfg = config_load("/etc/xcb/pd.conf"))) {
		char *cat = category_browse(cfg, NULL);

		while (cat) {
			if (!strcasecmp(cat, "pair")) {
				struct variable *var = variable_browse(cfg, cat);
				struct cpl *cpl = NULL;

				while (var) {
					if (!strcasecmp(var->name, "contract1")) {
						if (!strcasecmp(var->value, ""))
							break;
						if (cpl == NULL) {
							if (NEW(cpl) == NULL)
								break;
							cpl->contract2 = NULL;
							cpl->price1 = cpl->price2 = cpl->prevpd = -1.0;
							pthread_spin_init(&cpl->lock, 0);
						}
						cpl->contract1 = var->value;

					} else if (!strcasecmp(var->name, "contract2")) {
						if (!strcasecmp(var->value, ""))
							break;
						if (cpl == NULL) {
							if (NEW(cpl) == NULL)
								break;
							cpl->contract1 = NULL;
							cpl->price1 = cpl->price2 = cpl->prevpd = -1.0;
							pthread_spin_init(&cpl->lock, 0);
						}
						cpl->contract2 = var->value;
					} else
						xcb_log(XCB_LOG_WARNING, "Unknown variable '%s' in "
							"category '%s' of pd.conf", var->name, cat);
					var = var->next;
				}
				if (cpl && cpl->contract1 && cpl->contract2) {
					dlist_t dlist;

					if ((dlist = table_get_value(contracts, cpl->contract1)) == NULL) {
						dlist = dlist_new(NULL, NULL);
						table_insert(contracts, cpl->contract1, dlist);
					}
					dlist_insert_tail(dlist, cpl);
					if ((dlist = table_get_value(contracts, cpl->contract2)) == NULL) {
						dlist = dlist_new(NULL, NULL);
						table_insert(contracts, cpl->contract2, dlist);
					}
					dlist_insert_tail(dlist, cpl);
					dlist_insert_tail(pairs, cpl);
				} else if (cpl)
					FREE(cpl);
			}
			cat = category_browse(cfg, cat);
		}
	}
}

static int pd_exec(void *data, void *data2) {
	RAII_VAR(struct msg *, msg, (struct msg *)data, msg_decr);
	Quote *quote = (Quote *)msg->data;
	dlist_t dlist;
	NOT_USED(data2);

	if ((dlist = table_get_value(contracts, quote->thyquote.m_cHYDM))) {
		dlist_iter_t iter = dlist_iter_new(dlist, DLIST_START_HEAD);
		dlist_node_t node;

		while ((node = dlist_next(iter))) {
			struct cpl *cpl = (struct cpl *)dlist_node_value(node);

			pthread_spin_lock(&cpl->lock);
			if (!strcasecmp(cpl->contract1, quote->thyquote.m_cHYDM))
				cpl->price1 = quote->thyquote.m_dZXJ;
			else
				cpl->price2 = quote->thyquote.m_dZXJ;
			if (cpl->price1 > 0.0 && cpl->price2 > 0.0) {
				float pd = fabs(cpl->price1 - cpl->price2);

				/* If the price diff changes, we output it. */
				if (fabs(pd - cpl->prevpd) > 0.000001) {
					time_t t = (time_t)quote->thyquote.m_nTime;
					struct tm lt;
					char datestr[64], res[512];

					strftime(datestr, sizeof datestr, "%F %T", localtime_r(&t, &lt));
					snprintf(res, sizeof res, "PD,%s.%03d,%s,%s|%.2f,%.2f,%.2f",
						datestr,
						quote->m_nMSec,
						cpl->contract1,
						cpl->contract2,
						cpl->price1,
						cpl->price2,
						pd);
					out2rmp(res);
					cpl->prevpd = pd;
				}
			}
			pthread_spin_unlock(&cpl->lock);
		}
	}
	return 0;
}

static void lfree(void *value) {
	dlist_t dlist = (dlist_t)value;

	dlist_free(&dlist);
}

static void vfree(void *value) {
	struct cpl *cpl = (struct cpl *)value;

	pthread_spin_destroy(&cpl->lock);
	FREE(cpl);
}

static int load_module(void) {
	contracts = table_new(cmpstr, hashmurmur2, NULL, lfree);
	pairs = dlist_new(NULL, vfree);
	load_config();
	if (msgs_hook(&default_msgs, pd_exec, NULL) == -1)
		return MODULE_LOAD_FAILURE;
	return register_application(app, pd_exec, desc, fmt, mod_info->self);
}

static int unload_module(void) {
	msgs_unhook(&default_msgs, pd_exec);
	dlist_free(&pairs);
	table_free(&contracts);
	config_destroy(cfg);
	return unregister_application(app);
}

static int reload_module(void) {
	msgs_unhook(&default_msgs, pd_exec);
	dlist_free(&pairs);
	table_clear(contracts);
	config_destroy(cfg);
	load_config();
	if (msgs_hook(&default_msgs, pd_exec, NULL) == -1)
		return MODULE_LOAD_FAILURE;
	return MODULE_LOAD_SUCCESS;
}

MODULE_INFO(load_module, unload_module, reload_module, "Price Difference Application");

