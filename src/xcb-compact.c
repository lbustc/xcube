/*
 * Copyright (c) 2013-2015, Dalian Futures Information Technology Co., Ltd.
 *
 * Bo Wang     <futurewb at dce dot com dot cn>
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
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#ifdef __linux__
#define CONFIG_HAVE_BACKTRACE 1
#include <execinfo.h>
#endif
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "macros.h"
#include "mem.h"
#include "dlist.h"
#include "table.h"
#include "dstr.h"
#include "logger.h"
#include "config.h"
#include "module.h"
#include "net.h"
#include "event.h"
#include "thrpool.h"
#include "db.h"
#include "utilities.h"
#include "basics.h"
#include "commons.h"

/* FIXME */
struct sms {
	int32_t	qsec, sec, msec;
};

/* FIXME */
table_t cache;
table_t subscribers;
struct msgs default_msgs = {
	.name    = "default_msgs",
	.first   = NULL,
	.last    = NULL,
	.lock    = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP,
	.cond    = PTHREAD_COND_INITIALIZER,
	.thread  = (pthread_t)-1,
	.appouts = NULL,
};
dlist_t clients_to_close;
table_t idxfmts;
event_loop el;
int persistence = 0;
db_t *db;
db_readoptions_t *db_ro;
const char *password;
const char *dpip;
int dpport;

/* FIXME */
void client_free(client c);
static void tcp_accept_handler(event_loop el, int fd, int mask, void *data);
static void help_command(client c);
static void config_command(client c);
static void show_command(client c);
static void module_command(client c);
static void monitor_command(client c);
static void database_command(client c);
static void shutdown_command(client c);
extern void s_command(client c);
extern void u_command(client c);
extern void q_command(client c);
extern void qc_command(client c);
extern void index_command(client c);
extern void auth_command(client c);

/* FIXME */
static table_t cmds;
static struct cmd commands[] = {
	{"help",	help_command,		"Display this text",			1},
	{"?",		help_command,		"Synonym for 'help'",			1},
	{"config",	config_command,		"Get or set configurations",		-3},
	{"show",	show_command,		"Show modules, applictions or queues",	2},
	{"module",	module_command,		"Load, unload or reload module",	3},
	{"monitor",	monitor_command,	"Monitor on or off",			2},
	{"database",	database_command,	"Database operations",			-2},
	{"shutdown",	shutdown_command,	"Shut down xcb-compact",		1},
	{"quit",	NULL,			"Quit connecting to xcb-compact",	1}
};
static table_t ctm_cmds;
static struct cmd ctm_commands[] = {
	{"S",		s_command,		"Subscribe",				-1},
	{"U",		u_command,		"Unsubscribe",				-1},
	{"Q",		q_command,		"Query",				5},
	{"QC",		qc_command,		"Query cancellation",			2},
	{"INDEX",	index_command,		"Index",				2},
	{"AUTH",	auth_command,		"Authenticate",				2},
	{"QUIT",	NULL,			"Quit connecting to xcb-compact",	1}
};
static struct config *cfg;
static pthread_mutex_t cfg_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static const char *cfg_path;
static int addms = 0;
static table_t times;
static dlist_t queues;
static dlist_t clients;
static dlist_t monitors;
static thrpool_t tp;
static dstr indices;
static dlist_t filter;
static db_options_t *db_o;
static db_writeoptions_t *db_wo;
static db_writebatch_t *db_wb;
static pthread_mutex_t wb_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static int dirty = 0;
static char neterr[256];
static int udpsock = -1;
static int tcpsock = -1;
static int ctmsock = -1;
static int log_reload = 0;
static int shut_down = 0;
static int cronloops = 0;

static void sig_hup_handler(int sig) {
	NOT_USED(sig);

	xcb_log(XCB_LOG_WARNING, "SIGHUP received, scheduling reload...");
	log_reload = 1;
}

#ifdef CONFIG_HAVE_BACKTRACE
static void sig_segv_handler(int sig, siginfo_t *info, void *secret) {
	ucontext_t *uc = (ucontext_t *)secret;
	int fd, trace_size = 0;
	void *trace[100];
	struct sigaction sa;
	NOT_USED(info);

	xcb_log(XCB_LOG_WARNING, "\n\n=== XCUBE BUG REPORT START: Cut & paste starting from here ===\n"
		"    xcb-compact crashed by signal: %d\n--- STACK TRACE", sig);
	close_logger();
	if ((fd = open("/var/log/xcb/xcb-compact.log", O_APPEND | O_CREAT | O_WRONLY, 0644)) == -1)
		return;
	trace_size = backtrace(trace, 100);
#ifdef __x86_64__
	trace[1] = (void *)uc->uc_mcontext.gregs[16];
#endif
	backtrace_symbols_fd(trace, trace_size, fd);
	write(fd, "\n=== XCUBE BUG REPORT END. Make sure to include from START to END. ===\n\n", 72);
	close(fd);
	sigemptyset(&sa.sa_mask);
	sa.sa_flags   = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
	sa.sa_handler = SIG_DFL;
	sigaction(sig, &sa, NULL);
	kill(getpid(), sig);
}
#endif

static void sig_term_handler(int sig) {
	NOT_USED(sig);

	xcb_log(XCB_LOG_WARNING, "SIGTERM received, scheduling shutdown...");
	shut_down = 1;
}

static void setup_signal_handlers(void) {
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags   = 0;
	sa.sa_handler = sig_hup_handler;
	sigaction(SIGHUP, &sa, NULL);
#ifdef CONFIG_HAVE_BACKTRACE
	sigemptyset(&sa.sa_mask);
	sa.sa_flags     = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
	sa.sa_sigaction = sig_segv_handler;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
#endif
	sigemptyset(&sa.sa_mask);
	sa.sa_flags   = 0;
	sa.sa_handler = sig_term_handler;
	sigaction(SIGTERM, &sa, NULL);
}

static void usage(void) {
	fprintf(stderr, "Usage: ./xcb-compact [-f] path/to/xcb-compact.conf\n");
	fprintf(stderr, "       ./xcb-compact -h or --help\n");
	exit(1);
}

/* FIXME */
static void kfree(const void *key) {
	dstr_free((dstr)key);
}

/* FIXME */
static void vfree(void *value) {
	FREE(value);
}

/* FIXME */
static void vfree2(void *value) {
	dstr_free((dstr)value);
}

/* FIXME */
static void lfree(void *value) {
	dlist_t dlist = (dlist_t)value;

	dlist_free(&dlist);
}

/* FIXME */
static void msgfree(void *value) {
	msg_decr((struct msg *)value);
}

/* FIXME */
static int prepare_for_shutdown(void) {
	xcb_log(XCB_LOG_WARNING, "User requested shutdown...");
	if (persistence) {
		pthread_mutex_lock(&wb_lock);
		db_close(&db);
		pthread_mutex_unlock(&wb_lock);
	}
	if (udpsock != -1)
		close(udpsock);
	if (tcpsock != -1)
		close(tcpsock);
	if (ctmsock != -1)
		close(ctmsock);
	xcb_log(XCB_LOG_WARNING, "xcb-compact is now ready to exit, bye bye...");
	close_logger();
	return 0;
}

static dstr get_indices(void) {
	dlist_iter_t iter, iter2;
	dlist_node_t node;
	dlist_t dlist = dlist_new(cmpstr, vfree2);
	dstr res = dstr_new("INDICES");

	dlist_lock(queues);
	iter = dlist_iter_new(queues, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		struct msgs *msgs = (struct msgs *)dlist_node_value(node);

		dlist_lock(msgs->appouts);
		iter2 = dlist_iter_new(msgs->appouts, DLIST_START_HEAD);
		while ((node = dlist_next(iter2))) {
			struct appout *ao = (struct appout *)dlist_node_value(node);
			const char *appname;

			if ((appname = get_application_name(ao->app))) {
				dstr index, format, prev;

				index  = dstr_new(appname);
				format = dstr_new(get_application_format(ao->app));
				STR2UPPER(index);
				if (dlist_find(dlist, index) == NULL)
					dlist_insert_sort(dlist, dstr_new(index));
				table_lock(idxfmts);
				if ((prev = table_get_value(idxfmts, index)) == NULL)
					table_insert(idxfmts, index, format);
				else if (dstr_length(prev) != dstr_length(format) ||
					memcmp(prev, format, dstr_length(prev))) {
					table_insert(idxfmts, index, format);
					dstr_free(prev);
					dstr_free(index);
				} else {
					dstr_free(format);
					dstr_free(index);
				}
				table_unlock(idxfmts);
			}
		}
		dlist_iter_free(&iter2);
		dlist_unlock(msgs->appouts);
	}
	dlist_iter_free(&iter);
	dlist_unlock(queues);
	/* assemble */
	iter = dlist_iter_new(dlist, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		dstr index = (dstr)dlist_node_value(node);

		res = dstr_cat(res, ",");
		res = dstr_cat(res, index);
	}
	dlist_iter_free(&iter);
	dlist_free(&dlist);
	res = dstr_cat(res, "\r\n");
	return res;
}

static int server_cron(event_loop el, unsigned long id, void *data) {
	dlist_iter_t iter;
	dlist_node_t node;
	NOT_USED(el);
	NOT_USED(id);
	NOT_USED(data);

	if (log_reload) {
		close_logger();
		if (init_logger("/var/log/xcb/xcb-compact.log", __LOG_DEBUG) == 0) {
			const char *tmp;

			pthread_mutex_lock(&cfg_lock);
			if ((tmp = variable_retrieve(cfg, "general", "log_level"))) {
				if (!strcasecmp(tmp, "debug"))
					set_logger_level(__LOG_DEBUG);
				else if (!strcasecmp(tmp, "info"))
					set_logger_level(__LOG_INFO);
				else if (!strcasecmp(tmp, "notice"))
					set_logger_level(__LOG_NOTICE);
				else if (!strcasecmp(tmp, "warning"))
					set_logger_level(__LOG_WARNING);
			}
			pthread_mutex_unlock(&cfg_lock);
			log_reload = 0;
		}
		/* FIXME */
		if (addms)
			table_clear(times);
		table_lock(cache);
		table_clear(cache);
		table_unlock(cache);
	}
	if (shut_down) {
		if (prepare_for_shutdown() == 0)
			exit(0);
		xcb_log(XCB_LOG_WARNING, "SIGTERM received, but errors trying to shutdown the server");
	}
	/* FIXME */
	iter = dlist_iter_new(clients_to_close, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		client c = (client)dlist_node_value(node);

		if (c->refcount == 0)
			client_free(c);
	}
	dlist_iter_free(&iter);
	/* FIXME */
	if (cronloops % 10 == 0)
		if (persistence && dirty) {
			char *dberr = NULL;

			pthread_mutex_lock(&wb_lock);
			db_write(db, db_wo, db_wb, &dberr);
			if (dberr) {
				xcb_log(XCB_LOG_WARNING, "Writing data batch: %s", dberr);
				db_free(dberr);
			}
			db_writebatch_clear(db_wb);
			pthread_mutex_unlock(&wb_lock);
			dirty = 0;
		}
	/* FIXME */
	if (cronloops % 200 == 0) {
		dstr res;

		/* heartbeat */
		dlist_lock(clients);
		if (dlist_length(clients) > 0) {
			dstr ip = getipv4();

			res = dstr_new("HEARTBEAT|");
			res = dstr_cat(res, ip);
			res = dstr_cat(res, "\r\n");
			iter = dlist_iter_new(clients, DLIST_START_HEAD);
			while ((node = dlist_next(iter))) {
				client c = (client)dlist_node_value(node);

				if (c->sock != ctmsock) {
					pthread_spin_lock(&c->lock);
					if (net_try_write(c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1)
						xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
							c, strerror(errno));
					pthread_spin_unlock(&c->lock);
				}
			}
			dlist_iter_free(&iter);
			dstr_free(ip);
			dstr_free(res);
		}
		dlist_unlock(clients);
		/* indices */
		res = get_indices();
		if (indices == NULL || dstr_length(indices) != dstr_length(res) ||
			memcmp(indices, res, dstr_length(indices))) {
			dlist_lock(clients);
			if (dlist_length(clients) > 0) {
				iter = dlist_iter_new(clients, DLIST_START_HEAD);
				while ((node = dlist_next(iter))) {
					client c = (client)dlist_node_value(node);

					pthread_spin_lock(&c->lock);
					if (net_try_write(c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1)
						xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
							c, strerror(errno));
					pthread_spin_unlock(&c->lock);
				}
				dlist_iter_free(&iter);
			}
			dlist_unlock(clients);
			dstr_free(indices);
			indices = res;
		} else
			dstr_free(res);
	}
	++cronloops;
	return 100;
}

static int send_quote(void *data, void *data2) {
	struct msg *msg = (struct msg *)data;
	dstr skey = (dstr)data2;
	dstr *fields = NULL;
	int nfield = 0;
	dstr key, value, index, res;
	dlist_t dlist;

	/* FIXME */
	fields = dstr_split_len(msg->data, strlen(msg->data), "|", 1, &nfield);
	key   = dstr_new(fields[0]);
	value = dstr_new(fields[1]);
	dstr_free_tokens(fields, nfield);
	fields = NULL, nfield = 0;
	fields = dstr_split_len(key, dstr_length(key), ",", 1, &nfield);
	index = dstr_new(fields[0]);
	res = dstr_new(key);
	res = dstr_cat(res, ",");
	res = dstr_cat(res, value);
	res = dstr_cat(res, "\r\n");
	table_rwlock_rdlock(subscribers);
	if ((dlist = table_get_value(subscribers, index))) {
		dlist_iter_t iter = dlist_iter_new(dlist, DLIST_START_HEAD);
		dlist_node_t node;

		/* still has room to improve */
		while ((node = dlist_next(iter))) {
			struct kvd *kvd = (struct kvd *)dlist_node_value(node);

			if (dstr_length(kvd->key) <= dstr_length(skey) &&
				!memcmp(kvd->key, skey, dstr_length(kvd->key))) {
				dlist_iter_t iter2 = dlist_iter_new(kvd->u.dlist, DLIST_START_HEAD);

				while ((node = dlist_next(iter2))) {
					client c = (client)dlist_node_value(node);

					pthread_spin_lock(&c->lock);
					if (c->flags & CLIENT_CLOSE_ASAP) {
						pthread_spin_unlock(&c->lock);
						continue;
					}
					if (net_try_write(c->fd, res, dstr_length(res), 10, NET_NONBLOCK) == -1) {
						xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
							c, strerror(errno));
						if (++c->eagcount >= 10)
							client_free_async(c);
					} else if (c->eagcount)
						c->eagcount = 0;
					pthread_spin_unlock(&c->lock);
				}
				dlist_iter_free(&iter2);
			}
		}
		dlist_iter_free(&iter);
	}
	table_rwlock_unlock(subscribers);
	dstr_free(res);
	dstr_free(index);
	dstr_free(value);
	dstr_free(key);
	dstr_free_tokens(fields, nfield);
	dstr_free(skey);
	msg_decr(msg);
	return 0;
}

/* worker thread */
static void *wk_thread(void *data) {
	struct msg *next = NULL, *msg;
	struct msgs *msgs = (struct msgs *)data;

	for (;;) {
		if (next == NULL) {
			pthread_mutex_lock(&msgs->lock);
			pthread_cleanup_push(pthread_mutex_unlock, &msgs->lock);
			if (msgs->first == NULL) {
				if (shut_down)
					break;
				else
					pthread_cond_wait(&msgs->cond, &msgs->lock);
			}
			next = msgs->first;
			msgs->first = NULL;
			msgs->last  = NULL;
			pthread_cleanup_pop(1);
		} else {
			Quote *quote;

			msg = next;
			next = msg->link;
			quote = (Quote *)msg->data;
			if (msgs != &default_msgs || quote->thyquote.m_nLen == sizeof (THYQuote)) {
				dlist_lock(msgs->appouts);
				if (dlist_length(msgs->appouts) > 0) {
					dlist_iter_t iter = dlist_iter_new(msgs->appouts, DLIST_START_HEAD);
					dlist_node_t node;

					msg_ref(msg, dlist_length(msgs->appouts));
					while ((node = dlist_next(iter))) {
						struct appout *ao = (struct appout *)dlist_node_value(node);

						thrpool_queue(tp, ao->app, msg, ao->out, msgfree, NULL);
					}
					dlist_iter_free(&iter);
				}
				dlist_unlock(msgs->appouts);
			} else {
				int (*exec)(void *data, void *data2);

				/* reverse plain old string for testing */
				if ((exec = get_application("test"))) {
					msg_incr(msg);
					thrpool_queue(tp, exec, msg, NULL, msgfree, NULL);
				} else
					out2rmp(msg->data);
			}
			msg_decr(msg);
		}
		if (shut_down)
			break;
	}
	return NULL;
}

static void read_quote(event_loop el, int fd, int mask, void *data) {
	char *buf;
	struct sockaddr_in si;
	socklen_t slen = sizeof si;
	int nread;
	NOT_USED(el);
	NOT_USED(mask);
	NOT_USED(data);

	if ((buf = CALLOC(1, sizeof (Quote))) == NULL)
		return;
	/* FIXME */
	if ((nread = recvfrom(fd, buf, sizeof (Quote), 0, (struct sockaddr *)&si, &slen)) > 0) {
		Quote *quote;
		struct msg *msg;

		quote = (Quote *)buf;
		if (quote->thyquote.m_nLen == sizeof (THYQuote)) {
			dlist_iter_t iter;
			dlist_node_t node;
			int tlen;

			quote->thyquote.m_cJYS[sizeof quote->thyquote.m_cJYS - 1] = '\0';
			quote->thyquote.m_cHYDM[sizeof quote->thyquote.m_cHYDM - 1] = '\0';
			quote->m_nMSec = 0;
			/* for testing */
			dlist_rwlock_rdlock(monitors);
			if (dlist_length(monitors) > 0) {
				char res[512];

				snprintf(res, sizeof res, "RX '%d,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
					"%.2f,%.2f,%d,%.2f,%d,%d,%.2f,%d,%.2f,%d'\r\n",
					quote->thyquote.m_nTime,
					quote->thyquote.m_cHYDM,
					quote->thyquote.m_cJYS,
					quote->thyquote.m_dZXJ,
					quote->thyquote.m_dJKP,
					quote->thyquote.m_dZGJ,
					quote->thyquote.m_dZDJ,
					quote->thyquote.m_dZSP,
					quote->thyquote.m_dJSP,
					quote->thyquote.m_dZJSJ,
					quote->thyquote.m_dJJSJ,
					quote->thyquote.m_nCJSL,
					quote->thyquote.m_dCJJE,
					quote->thyquote.m_nZCCL,
					quote->thyquote.m_nCCL,
					quote->thyquote.m_dMRJG1,
					quote->thyquote.m_nMRSL1,
					quote->thyquote.m_dMCJG1,
					quote->thyquote.m_nMCSL1);
				iter = dlist_iter_new(monitors, DLIST_START_HEAD);
				while ((node = dlist_next(iter))) {
					client c = (client)dlist_node_value(node);

					pthread_spin_lock(&c->lock);
					if (c->flags & CLIENT_CLOSE_ASAP) {
						pthread_spin_unlock(&c->lock);
						continue;
					}
					if (net_try_write(c->fd, res, strlen(res), 10, NET_NONBLOCK) == -1) {
						xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
							c, strerror(errno));
						if (++c->eagcount >= 10)
							client_free_async(c);
					} else if (c->eagcount)
						c->eagcount = 0;
					pthread_spin_unlock(&c->lock);
				}
				dlist_iter_free(&iter);
			}
			dlist_rwlock_unlock(monitors);
			/* FIXME: filter */
			iter = dlist_iter_new(filter, DLIST_START_HEAD);
			while ((node = dlist_next(iter))) {
				dstr item = (dstr)dlist_node_value(node);

				if (dstr_length(item) <= sizeof quote->thyquote.m_cHYDM &&
					!memcmp(item, quote->thyquote.m_cHYDM, dstr_length(item)))
					break;
			}
			dlist_iter_free(&iter);
			if (node == NULL) {
				FREE(buf);
				return;
			}
			/* FIXME */
			if (quote->thyquote.m_nTime == 999999999) {
				FREE(buf);
				return;
			} else if ((tlen = intlen(quote->thyquote.m_nTime)) < 10) {
				struct timeval tv;
				struct tm lt;

				gettimeofday(&tv, NULL);
				localtime_r(&tv.tv_sec, &lt);
				if (quote->thyquote.m_cHYDM[0] == 'S' && quote->thyquote.m_cHYDM[1] == 'P')
					quote->thyquote.m_nTime *= 1000;
				else if (tlen == 6 || tlen == 7)
					quote->thyquote.m_nTime *= 100;
				lt.tm_hour = quote->thyquote.m_nTime / 10000000;
				lt.tm_min  = quote->thyquote.m_nTime % 10000000 / 100000;
				lt.tm_sec  = quote->thyquote.m_nTime % 100000   / 1000;
				quote->m_nMSec = quote->thyquote.m_nTime % 1000;
				quote->thyquote.m_nTime = mktime(&lt);
			}
			/* FIXME */
			if (addms) {
				struct timeval tv;
				dstr contract = dstr_new(quote->thyquote.m_cHYDM);
				struct sms *sms;

				gettimeofday(&tv, NULL);
				if ((sms = table_get_value(times, contract)) == NULL) {
					if (NEW(sms)) {
						sms->qsec = quote->thyquote.m_nTime;
						sms->sec  = tv.tv_sec;
						sms->msec = tv.tv_usec / 1000;
						table_insert(times, contract, sms);
					}
				} else if (sms->qsec != quote->thyquote.m_nTime) {
					sms->qsec = quote->thyquote.m_nTime;
					sms->sec  = tv.tv_sec;
					sms->msec = tv.tv_usec / 1000;
					dstr_free(contract);
				} else {
					int32_t offset;

					if ((offset = (tv.tv_sec - sms->sec) * 1000 +
						tv.tv_usec / 1000 - sms->msec) > 999)
						offset = 999;
					quote->m_nMSec = offset;
					dstr_free(contract);
				}
			}
			if (get_logger_level() == __LOG_DEBUG) {
				time_t t = (time_t)quote->thyquote.m_nTime;
				char datestr[64];

				strftime(datestr, sizeof datestr, "%F %T", localtime(&t));
				xcb_log(XCB_LOG_DEBUG, "%s.%03d,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
					"%d,%.2f,%d,%d,%.2f,%d,%.2f,%d",
					datestr,
					quote->m_nMSec,
					quote->thyquote.m_cHYDM,
					quote->thyquote.m_cJYS,
					quote->thyquote.m_dZXJ,
					quote->thyquote.m_dJKP,
					quote->thyquote.m_dZGJ,
					quote->thyquote.m_dZDJ,
					quote->thyquote.m_dZSP,
					quote->thyquote.m_dJSP,
					quote->thyquote.m_dZJSJ,
					quote->thyquote.m_dJJSJ,
					quote->thyquote.m_nCJSL,
					quote->thyquote.m_dCJJE,
					quote->thyquote.m_nZCCL,
					quote->thyquote.m_nCCL,
					quote->thyquote.m_dMRJG1,
					quote->thyquote.m_nMRSL1,
					quote->thyquote.m_dMCJG1,
					quote->thyquote.m_nMCSL1);
			}
		} else
			xcb_log(XCB_LOG_DEBUG, "Data '%s' received", buf);
		if (NEW0(msg) == NULL) {
			FREE(buf);
			return;
		}
		msg->data     = buf;
		msg->refcount = 1;
		pthread_mutex_lock(&default_msgs.lock);
		if (default_msgs.first == NULL)
			default_msgs.last = default_msgs.first = msg;
		else {
			default_msgs.last->link = msg;
			default_msgs.last = msg;
		}
		pthread_cond_signal(&default_msgs.cond);
		pthread_mutex_unlock(&default_msgs.lock);
	} else
		FREE(buf);
}

/* FIXME */
int msgs_init(struct msgs **msgs, const char *name, struct module *mod) {
	pthread_mutexattr_t attr;

	if (name == NULL)
		name = "";
	if (mod == NULL)
		return -1;
	if (NEW(*msgs) == NULL)
		return -1;
	if (((*msgs)->name = mem_strdup(name)) == NULL) {
		FREEMSGS(*msgs);
		return -1;
	}
	(*msgs)->mod     = mod;
	(*msgs)->first   = NULL;
	(*msgs)->last    = NULL;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&(*msgs)->lock, &attr);
	pthread_mutexattr_destroy(&attr);
	pthread_cond_init(&(*msgs)->cond, NULL);
	(*msgs)->thread  = (pthread_t)-1;
	(*msgs)->appouts = dlist_new(NULL, NULL);
	/* join global queue */
	dlist_lock(queues);
	dlist_insert_tail(queues, *msgs);
	dlist_unlock(queues);
	return 0;
}

/* FIXME */
void msgs_free(struct msgs *msgs) {
	dlist_node_t node;

	dlist_lock(queues);
	if ((node = dlist_find(queues, msgs)))
		dlist_remove(queues, node);
	dlist_unlock(queues);
	FREEMSGS(msgs);
}

/* FIXME */
int msgs_hook(struct msgs *msgs, int (*exec)(void *data, void *data2), struct msgs *out) {
	struct appout *ao;

	if (msgs == NULL || exec == NULL)
		return -1;
	if (NEW(ao) == NULL)
		return -1;
	ao->app = exec;
	ao->out = out;
	dlist_lock(msgs->appouts);
	dlist_insert_tail(msgs->appouts, ao);
	dlist_unlock(msgs->appouts);
	return 0;
}

/* FIXME */
int msgs_hook_name(const char *msgs, int (*exec)(void *data, void *data2), struct msgs *out) {
	dlist_iter_t iter;
	dlist_node_t node;

	if (msgs == NULL || exec == NULL)
		return -1;
	dlist_lock(queues);
	iter = dlist_iter_new(queues, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		struct msgs *m = (struct msgs *)dlist_node_value(node);

		if (!strcasecmp(m->name, msgs)) {
			if (msgs_hook(m, exec, out) == -1) {
				dlist_unlock(queues);
				return -1;
			}
			break;
		}
	}
	dlist_iter_free(&iter);
	dlist_unlock(queues);
	return node ? 0 : -2;
}

/* FIXME */
void msgs_unhook(struct msgs *msgs, int (*exec)(void *data, void *data2)) {
	dlist_iter_t iter;
	dlist_node_t node;

	if (msgs == NULL || exec == NULL)
		return;
	dlist_lock(msgs->appouts);
	iter = dlist_iter_new(msgs->appouts, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		struct appout *ao = (struct appout *)dlist_node_value(node);

		if (ao->app == exec) {
			dlist_remove(msgs->appouts, node);
			FREE(ao);
		}
	}
	dlist_iter_free(&iter);
	dlist_unlock(msgs->appouts);
	thrpool_remove(tp, exec);
}

/* FIXME */
void msgs_unhook_name(const char *msgs, int (*exec)(void *data, void *data2)) {
	dlist_iter_t iter;
	dlist_node_t node;

	if (msgs == NULL || exec == NULL)
		return;
	dlist_lock(queues);
	iter = dlist_iter_new(queues, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		struct msgs *m = (struct msgs *)dlist_node_value(node);

		if (!strcasecmp(m->name, msgs))
			msgs_unhook(m, exec);
	}
	dlist_iter_free(&iter);
	dlist_unlock(queues);
	thrpool_remove(tp, exec);
}

/* FIXME */
int start_msgs(struct msgs *msgs) {
	if (msgs == NULL)
		return -1;
	if (pthread_create(&msgs->thread, NULL, wk_thread, msgs) != 0) {
		xcb_log(XCB_LOG_ERROR, "Error initializing worker thread");
		return -1;
	}
	return 0;
}

/* FIXME */
void stop_msgs(struct msgs *msgs) {
	if (msgs == NULL)
		return;
	pthread_cancel(msgs->thread);
}

/* FIXME */
int check_msgs(struct msgs *msgs) {
	dlist_iter_t iter;
	dlist_node_t node;
	int flag = 0;

	dlist_lock(msgs->appouts);
	iter = dlist_iter_new(msgs->appouts, DLIST_START_HEAD);
	while ((node = dlist_next(iter))) {
		struct appout *ao = (struct appout *)dlist_node_value(node);;
		struct module *mod;

		if ((mod = get_application_module(ao->app)) != msgs->mod) {
			xcb_log(XCB_LOG_WARNING, "Queue '%s' is used by module '%s', unload '%s' first",
				msgs->name, mod->name, mod->name);
			flag = -1;
		}
	}
	dlist_iter_free(&iter);
	dlist_unlock(msgs->appouts);
	return flag;
}

/* FIXME */
void out2rmp(const char *res) {
	if (res) {
		int len = strlen(res);
		struct msg *msg;
		dstr *fields = NULL;
		int nfield = 0;

		if (NEW0(msg) == NULL)
			return;
		if ((msg->data = mem_strndup(res, len)) == NULL) {
			FREEMSG(msg);
			return;
		}
		msg->refcount = 1;
		fields = dstr_split_len(res, len, "|", 1, &nfield);
		{
			dstr key = NULL, value = NULL, index = NULL, contracts = NULL;
			dstr ckey, cvalue, skey;
			dlist_t dlist;
			struct kvd *kvd;
			dlist_node_t node;

			if (nfield != 2)
				goto end;
			key   = dstr_new(fields[0]);
			value = dstr_new(fields[1]);
			dstr_free_tokens(fields, nfield);
			fields = NULL, nfield = 0;
			fields = dstr_split_len(key, dstr_length(key), ",", 1, &nfield);
			if (nfield < 2)
				goto end;
			index = dstr_new(fields[0]);
			if (nfield > 2) {
				int i;

				contracts = dstr_new(fields[2]);
				for (i = 3; i < nfield; ++i) {
					contracts = dstr_cat(contracts, ",");
					contracts = dstr_cat(contracts, fields[i]);
				}
			}
			ckey   = dstr_new(index);
			if (contracts) {
				ckey = dstr_cat(ckey, ",");
				ckey = dstr_cat(ckey, contracts);
			}
			cvalue = dstr_new(fields[1]);
			cvalue = dstr_cat(cvalue, ",");
			cvalue = dstr_cat(cvalue, value);
			skey   = dstr_new(ckey);
			table_lock(cache);
			if ((dlist = table_get_value(cache, index)) == NULL) {
				if (NEW(kvd)) {
					kvd->key     = ckey;
					kvd->u.value = cvalue;
					dlist = dlist_new(cmpkvd, kvfree);
					dlist_insert_sort(dlist, kvd);
					table_insert(cache, dstr_new(index), dlist);
				} else {
					xcb_log(XCB_LOG_ERROR, "Error allocating memory for kvd");
					dstr_free(cvalue);
					dstr_free(ckey);
				}
			} else {
				if (NEW(kvd)) {
					kvd->key     = ckey;
					kvd->u.value = NULL;
					if ((node = dlist_find(dlist, kvd)) == NULL) {
						kvd->u.value = cvalue;
						dlist_insert_sort(dlist, kvd);
					} else {
						FREE(kvd);
						kvd = (struct kvd *)dlist_node_value(node);
						if (dstr_length(kvd->u.value) == dstr_length(cvalue) &&
							!memcmp(kvd->u.value, cvalue, dstr_length(kvd->u.value))) {
							dstr_free(skey);
							dstr_free(cvalue);
							dstr_free(ckey);
							table_unlock(cache);
							goto end;
						}
						dstr_free(kvd->u.value);
						kvd->u.value = cvalue;
						dstr_free(ckey);
					}
				} else {
					xcb_log(XCB_LOG_ERROR, "Error allocating memory for kvd");
					dstr_free(cvalue);
					dstr_free(ckey);
				}
			}
			table_unlock(cache);
			msg_incr(msg);
			thrpool_queue(tp, send_quote, msg, skey, msgfree, vfree2);
			/* FIXME */
			if (persistence) {
				pthread_mutex_lock(&wb_lock);
				db_writebatch_put(db_wb, key, value);
				pthread_mutex_unlock(&wb_lock);
				dirty = 1;
			}

end:
			/* for testing */
			dlist_rwlock_rdlock(monitors);
			if (dlist_length(monitors) > 0) {
				dstr res = dstr_new("TX '");
				dlist_iter_t iter = dlist_iter_new(monitors, DLIST_START_HEAD);

				if (key && value) {
					res = dstr_cat(res, key);
					res = dstr_cat(res, ",");
					res = dstr_cat(res, value);
				} else
					res = dstr_cat(res, msg->data);
				res = dstr_cat(res, "'\r\n");
				while ((node = dlist_next(iter))) {
					client c = (client)dlist_node_value(node);

					pthread_spin_lock(&c->lock);
					if (c->flags & CLIENT_CLOSE_ASAP) {
						pthread_spin_unlock(&c->lock);
						continue;
					}
					if (net_try_write(c->fd, res, dstr_length(res), 10, NET_NONBLOCK) == -1) {
						xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
							c, strerror(errno));
						if (++c->eagcount >= 10)
							client_free_async(c);
					} else if (c->eagcount)
						c->eagcount = 0;
					pthread_spin_unlock(&c->lock);
				}
				dlist_iter_free(&iter);
				dstr_free(res);
			}
			dlist_rwlock_unlock(monitors);
			dstr_free(contracts);
			dstr_free(index);
			dstr_free(value);
			dstr_free(key);
		}
		dstr_free_tokens(fields, nfield);
		msg_decr(msg);
	}
}

/* FIXME */
int out2msgs(char *res, struct msgs *msgs) {
	struct msg *msg;

	if (res == NULL || msgs == NULL)
		return -1;
	if (NEW0(msg) == NULL)
		return -1;
	msg->data     = res;
	msg->refcount = 1;
	pthread_mutex_lock(&msgs->lock);
	if (msgs->first == NULL)
		msgs->last = msgs->first = msg;
	else {
		msgs->last->link = msg;
		msgs->last = msg;
	}
	pthread_cond_signal(&msgs->cond);
	pthread_mutex_unlock(&msgs->lock);
	return 0;
}

int main(int argc, char **argv) {
	int ncmds, i;
	const char *tmp;

	/* FIXME */
	signal(SIGPIPE, SIG_IGN);
	setup_signal_handlers();
	cmds = table_new(cmpstr, hashmurmur2, NULL, NULL);
	ncmds = sizeof commands / sizeof (struct cmd);
	for (i = 0; i < ncmds; ++i) {
		struct cmd *cmd = commands + i;

		table_insert(cmds, cmd->name, cmd);
	}
	ctm_cmds = table_new(cmpstr, hashmurmur2, NULL, NULL);
	ncmds = sizeof ctm_commands / sizeof (struct cmd);
	for (i = 0; i < ncmds; ++i) {
		struct cmd *cmd = ctm_commands + i;

		table_insert(ctm_cmds, cmd->name, cmd);
	}
	if (argc != 2 && argc != 3)
		usage();
	else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
		usage();
	else if (argc == 3 && strcmp(argv[1], "-f"))
		usage();
	if (argc == 2 && daemon(1, 0) == -1)
		fprintf(stderr, "Error daemonizing: %s\n", strerror(errno));
	/* FIXME */
	if (init_logger("/var/log/xcb/xcb-compact.log", __LOG_DEBUG) == -1) {
		fprintf(stderr, "Error initializing logger\n");
		exit(1);
	}
	cfg_path = argc == 2 ? argv[1] : argv[2];
	if ((cfg = config_load(cfg_path)) == NULL)
		exit(1);
	if ((tmp = variable_retrieve(cfg, "general", "log_level"))) {
		if (!strcasecmp(tmp, "info"))
			set_logger_level(__LOG_INFO);
		else if (!strcasecmp(tmp, "notice"))
			set_logger_level(__LOG_NOTICE);
		else if (!strcasecmp(tmp, "warning"))
			set_logger_level(__LOG_WARNING);
	}
	/* FIXME */
	if (addms)
		times = table_new(cmpstr, hashmurmur2, kfree, vfree);
	cache = table_new(cmpstr, hashmurmur2, kfree, lfree);
	subscribers = table_new(cmpstr, hashmurmur2, kfree, lfree);
	default_msgs.appouts = dlist_new(NULL, NULL);
	queues = dlist_new(NULL, NULL);
	dlist_insert_head(queues, &default_msgs);
	clients_to_close = dlist_new(NULL, NULL);
	clients = dlist_new(NULL, NULL);
	monitors = dlist_new(NULL, NULL);
	tp = thrpool_new(16, 512, 200, NULL);
	idxfmts = table_new(cmpstr, hashmurmur2, NULL, NULL);
	/* FIXME */
	if ((el = create_event_loop(1024 + 1000)) == NULL) {
		xcb_log(XCB_LOG_ERROR, "Error creating event loop");
		goto err;
	}
	create_time_event(el, 1, server_cron, NULL, NULL);
	/* FIXME */
	if ((tmp = variable_retrieve(cfg, "modules", "module_path")) && strcmp(tmp, "")) {
		struct variable *var = variable_browse(cfg, "modules");
		dlist_t noloads = dlist_new(cmpstr, NULL);
		DIR *dir;
		struct dirent *dirent;

		while (var) {
			if (!strcasecmp(var->name, "preload")) {
				if (strcmp(var->value, "")) {
					int len = strlen(var->value);

					if (len >= 4 && !strcasecmp(var->value + len - 3, ".so"))
						module_load(tmp, var->value);
				}
			} else if (!strcasecmp(var->name, "noload"))
				if (strcmp(var->value, ""))
					dlist_insert_tail(noloads, (void *)var->value);
			var = var->next;
		}
		if ((dir = opendir(tmp))) {
			while ((dirent = readdir(dir))) {
				int len = strlen(dirent->d_name);

				if (len < 4)
					continue;
				if (strcasecmp(dirent->d_name + len - 3, ".so"))
					continue;
				if (dlist_find(noloads, dirent->d_name))
					continue;
				module_load(tmp, dirent->d_name);
			}
			closedir(dir);
		} else
			xcb_log(XCB_LOG_WARNING, "Unable to open modules directory '%s'", tmp);
		dlist_free(&noloads);
	}
	if (pthread_create(&default_msgs.thread, NULL, wk_thread, &default_msgs) != 0) {
		xcb_log(XCB_LOG_ERROR, "Error initializing worker thread");
		goto err;
	}
	/* FIXME */
	filter = dlist_new(NULL, NULL);
	if ((tmp = variable_retrieve(cfg, "general", "filter"))) {
		dstr *fields = NULL;
		int nfield = 0;

		fields = dstr_split_len(tmp, strlen(tmp), ",", 1, &nfield);
		for (i = 0; i < nfield; ++i)
			dlist_insert_tail(filter, fields[i]);
	}
	/* FIXME */
	if ((tmp = variable_retrieve(cfg, "general", "persistence")))
		if (atoi(tmp) == 1)
			persistence = 1;
	if (persistence) {
		char *dberr = NULL;

		db_o = db_options_create();
		db = db_open(db_o, "/var/lib/xcb/db", &dberr);
		if (dberr) {
			xcb_log(XCB_LOG_ERROR, "Opening database: %s", dberr);
			db_free(dberr);
			goto err;
		}
		db_wo = db_writeoptions_create();
		db_wb = db_writebatch_create();
		db_ro = db_readoptions_create();
	}
	if ((tmp = variable_retrieve(cfg, "general", "password")) && strcmp(tmp, ""))
		password = tmp;
	if ((tmp = variable_retrieve(cfg, "dispatcher", "ip")) && strcmp(tmp, ""))
		dpip = tmp;
	if ((tmp = variable_retrieve(cfg, "dispatcher", "port")) && strcmp(tmp, ""))
		dpport = atoi(tmp);
	if ((tmp = variable_retrieve(cfg, "general", "udp_port")) && strcmp(tmp, "")) {
		if ((udpsock = net_udp_server(NULL, atoi(tmp), neterr, sizeof neterr)) == -1) {
			xcb_log(XCB_LOG_ERROR, "Opening port '%s': %s", tmp, neterr);
			goto err;
		}
		if (net_nonblock(udpsock, neterr, sizeof neterr) == -1) {
			xcb_log(XCB_LOG_ERROR, "Setting port '%s' nonblocking: %s", tmp, neterr);
			goto err;
		}
	}
	if ((tmp = variable_retrieve(cfg, "general", "tcp_port")) && strcmp(tmp, ""))
		if ((tcpsock = net_tcp_server(NULL, atoi(tmp), neterr, sizeof neterr)) == -1) {
			xcb_log(XCB_LOG_ERROR, "Opening port '%s': %s", tmp, neterr);
			goto err;
		}
	if ((tmp = variable_retrieve(cfg, "general", "ctm_port")) && strcmp(tmp, ""))
		if ((ctmsock = net_tcp_server(NULL, atoi(tmp), neterr, sizeof neterr)) == -1) {
			xcb_log(XCB_LOG_ERROR, "Opening port '%s': %s", tmp, neterr);
			goto err;
		}
	if (udpsock > 0 && create_file_event(el, udpsock, EVENT_READABLE, read_quote, NULL) == -1) {
		xcb_log(XCB_LOG_ERROR, "Unrecoverable error creating udpsock '%d' file event", udpsock);
		goto err;
	}
	if (tcpsock > 0 && create_file_event(el, tcpsock, EVENT_READABLE, tcp_accept_handler, NULL) == -1) {
		xcb_log(XCB_LOG_ERROR, "Unrecoverable error creating tcpsock '%d' file event", tcpsock);
		goto err;
	}
	if (ctmsock > 0 && create_file_event(el, ctmsock, EVENT_READABLE, tcp_accept_handler, NULL) == -1) {
		xcb_log(XCB_LOG_ERROR, "Unrecoverable error creating ctmsock '%d' file event", ctmsock);
		goto err;
	}
	xcb_log(XCB_LOG_NOTICE, "Server compact started");
	start_event_loop(el, ALL_EVENTS);
	delete_event_loop(el);
	return 0;

err:
	close_logger();
	exit(1);
}

/* FIXME */
static void remove_from_subscribers(client c) {
	table_iter_t titer;
	table_node_t tnode;

	table_rwlock_wrlock(subscribers);
	titer = table_iter_safe_new(subscribers);
	while ((tnode = table_next(titer))) {
		dlist_t dlist = (dlist_t)table_node_value(tnode);
		dlist_iter_t diter = dlist_iter_new(dlist, DLIST_START_HEAD);
		dlist_node_t node, node2;

		while ((node = dlist_next(diter))) {
			struct kvd *kvd = (struct kvd *)dlist_node_value(node);

			if ((node2 = dlist_find(kvd->u.dlist, c)))
				dlist_remove(kvd->u.dlist, node2);
			if (dlist_length(kvd->u.dlist) == 0) {
				dlist_remove(dlist, node);
				kdfree(kvd);
			}
		}
		dlist_iter_free(&diter);
		if (dlist_length(dlist) == 0) {
			table_remove(subscribers, table_node_key(tnode));
			dlist_free(&dlist);
		}
	}
	table_iter_free(&titer);
	table_rwlock_unlock(subscribers);
}

/* FIXME */
static void remove_from_monitors(client c) {
	dlist_node_t node;

	dlist_rwlock_wrlock(monitors);
	if ((node = dlist_find(monitors, c)))
		dlist_remove(monitors, node);
	dlist_rwlock_unlock(monitors);
}

/* FIXME */
static void remove_from_clients(client c) {
	dlist_node_t node;

	dlist_lock(clients);
	if ((node = dlist_find(clients, c)))
		dlist_remove(clients, node);
	dlist_unlock(clients);
}

static void client_reset(client c) {
	int i;

	for (i = 0; i < c->argc; ++i)
		dstr_free(c->argv[i]);
	c->argc = 0;
	c->cmd  = NULL;
}

void client_free(client c) {
	dlist_node_t node;

	remove_from_subscribers(c);
	remove_from_monitors(c);
	remove_from_clients(c);
	if (c->flags & CLIENT_CLOSE_ASAP && (node = dlist_find(clients_to_close, c)))
		dlist_remove(clients_to_close, node);
	delete_file_event(el, c->fd, EVENT_READABLE);
	delete_file_event(el, c->fd, EVENT_WRITABLE);
	ring_free(&c->reply);
	client_reset(c);
	FREE(c->argv);
	pthread_spin_destroy(&c->lock);
	close(c->fd);
	xcb_log(XCB_LOG_NOTICE, "Client '%p' got freed", c);
	FREE(c);
}

/* FIXME */
static int process_command(client c) {
	/* the quit command */
	if (!strcasecmp(c->argv[0], "quit")) {
		add_reply_string(c, "OK\r\n\r\n", 6);
		c->flags |= CLIENT_CLOSE_AFTER_REPLY;
		return -1;
	}
	if (c->sock == ctmsock) {
		dstr ctm_cmd = dstr_new_len(c->argv[0], 1);

		if (!strcmp(c->argv[0], "QC") || !strcmp(c->argv[0], "INDEX") ||
			!strcmp(c->argv[0], "AUTH") || !strcmp(c->argv[0], "XGTEST"))
			c->cmd = table_get_value(ctm_cmds, c->argv[0]);
		else {
			c->cmd = table_get_value(ctm_cmds, ctm_cmd);
			dstr_free(ctm_cmd);
		}
	} else
		c->cmd = table_get_value(cmds, c->argv[0]);
	if (c->cmd == NULL) {
		add_reply_error_format(c, "unknown command '%s'\r\n", c->argv[0]);
		return 0;
	} else if ((c->cmd->arity > 0 && c->cmd->arity != c->argc) || c->argc < -c->cmd->arity) {
		add_reply_error_format(c, "wrong number of arguments for command '%s'\r\n", c->argv[0]);
		return 0;
	}
	c->cmd->cproc(c);
	return 0;
}

void process_inbuf(client c) {
	while (c->inpos > 0) {
		char *newline;
		size_t len;

		if (c->flags & CLIENT_CLOSE_AFTER_REPLY)
			break;
		if ((newline = strstr(c->inbuf, "\r\n")) == NULL) {
			if (c->inpos == sizeof c->inbuf - 1) {
				add_reply_error(c, "protocol error: too big request\r\n");
				c->flags |= CLIENT_CLOSE_AFTER_REPLY;
				c->inpos = 0;
			}
			break;
		}
		len = newline - c->inbuf;
		if (c->argv)
			FREE(c->argv);
		/* FIXME */
		*newline = '\0';
		xcb_log(XCB_LOG_INFO, "Client '%p' issued command '%s'", c, c->inbuf);
		c->argv = c->sock == ctmsock ? dstr_split_len(c->inbuf, len, ",", 1, &c->argc)
			: dstr_split_args(c->inbuf, &c->argc);
		memmove(c->inbuf, c->inbuf + len + 2, sizeof c->inbuf - len - 2);
		c->inpos -= len + 2;
		if (c->argc == 0 || process_command(c) == 0)
			client_reset(c);
	}
}

static client client_new(int fd, int sock) {
	client c;

	if (NEW(c) == NULL)
		return NULL;
	/* FIXME */
	net_nonblock(fd, NULL, 0);
	net_tcp_nodelay(fd, NULL, 0);
	if (create_file_event(el, fd, EVENT_READABLE, read_from_client, c) == -1) {
		close(fd);
		client_free(c);
		return NULL;
	}
	c->fd            = fd;
	pthread_spin_init(&c->lock, 0);
	c->sock          = sock;
	c->flags         = 0;
	c->inpos         = 0;
	c->argc          = 0;
	c->argv          = NULL;
	c->outpos        = 0;
	c->reply         = ring_new();
	c->sentlen       = 0;
	c->refcount      = 0;
	c->eagcount      = 0;
	c->authenticated = 0;
	dlist_lock(clients);
	dlist_insert_tail(clients, c);
	dlist_unlock(clients);
	return c;
}

static void tcp_accept_handler(event_loop el, int fd, int mask, void *data) {
	char cip[128];
	int cport, cfd;
	client c;
	NOT_USED(el);
	NOT_USED(mask);
	NOT_USED(data);

	if ((cfd = net_tcp_accept(fd, cip, &cport, neterr, sizeof neterr)) == -1) {
		xcb_log(XCB_LOG_WARNING, "Accepting client connection: %s", neterr);
		return;
	}
	if ((c = client_new(cfd, fd)) == NULL) {
		xcb_log(XCB_LOG_WARNING, "Error registering fd '%d' event for the new client: %s",
			cfd, strerror(errno));
		close(cfd);
	} else if (c->sock != ctmsock) {
		/* heartbeat */
		dstr res = dstr_new("HEARTBEAT|");
		dstr ip = getipv4();

		xcb_log(XCB_LOG_NOTICE, "Accepted %s:%d, client '%p'", cip, cport, c);
		res = dstr_cat(res, ip);
		res = dstr_cat(res, "\r\n");
		res = dstr_cat(res, indices);
		pthread_spin_lock(&c->lock);
		if (net_try_write(c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1)
			xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s", c, strerror(errno));
		pthread_spin_unlock(&c->lock);
		dstr_free(ip);
		dstr_free(res);
	} else {
		xcb_log(XCB_LOG_NOTICE, "Accepted %s:%d, client '%p'", cip, cport, c);
		pthread_spin_lock(&c->lock);
		if (net_try_write(c->fd, indices, dstr_length(indices), 100, NET_NONBLOCK) == -1)
			xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s", c, strerror(errno));
		pthread_spin_unlock(&c->lock);
	}
}

static void help_command(client c) {
	int ncmds, i;

	ncmds = sizeof commands / sizeof (struct cmd);
	for (i = 0; i < ncmds; ++i) {
		struct cmd *cmd = commands + i;

		add_reply_string_format(c, "%30.30s  %s\r\n", cmd->name, cmd->doc);
	}
	add_reply_string(c, "\r\n", 2);
}

static void config_command(client c) {
	if (!strcasecmp(c->argv[1], "get")) {
		pthread_mutex_lock(&cfg_lock);
		if (!strcasecmp(c->argv[2], "log_level"))
			add_reply_string_format(c, "log_level:%s\r\n",
				variable_retrieve(cfg, "general", "log_level"));
		else if (!strcasecmp(c->argv[2], "filter"))
			add_reply_string_format(c, "filter:%s\r\n",
				variable_retrieve(cfg, "general", "filter"));
		else if (!strcasecmp(c->argv[2], "persistence"))
			add_reply_string_format(c, "persistence:%s\r\n",
				variable_retrieve(cfg, "general", "persistence"));
		else if (!strcasecmp(c->argv[2], "udp_port"))
			add_reply_string_format(c, "udp_port:%s\r\n",
				variable_retrieve(cfg, "general", "udp_port"));
		else if (!strcasecmp(c->argv[2], "ctm_port"))
			add_reply_string_format(c, "ctm_port:%s\r\n",
				variable_retrieve(cfg, "general", "ctm_port"));
		else
			add_reply_string(c, "-1\r\n", 4);
		pthread_mutex_unlock(&cfg_lock);
	} else if (!strcasecmp(c->argv[1], "set")) {
		struct category *category;

		pthread_mutex_lock(&cfg_lock);
		if (!strcasecmp(c->argv[2], "log_level") && c->argc >= 4) {
			category = category_get(cfg, "general");
			if (variable_update(category, "log_level", c->argv[3]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "filter") && c->argc >= 4) {
			category = category_get(cfg, "general");
			if (variable_update(category, "filter", c->argv[3]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "persistence") && c->argc >= 4) {
			category = category_get(cfg, "general");
			if (variable_update(category, "persistence", c->argv[3]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "udp_port") && c->argc >= 4) {
			category = category_get(cfg, "general");
			if (variable_update(category, "udp_port", c->argv[3]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "ctm_port") && c->argc >= 4) {
			category = category_get(cfg, "general");
			if (variable_update(category, "ctm_port", c->argv[3]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
		} else
			add_reply_string(c, "-1\r\n", 4);
		pthread_mutex_unlock(&cfg_lock);
	} else
		add_reply_error_format(c, "unknown action '%s'", c->argv[1]);
	add_reply_string(c, "\r\n", 2);
}

/* FIXME */
static void show_command(client c) {
	if (!strcasecmp(c->argv[1], "modules")) {
		struct module *mod = get_module_list_head();

		for (; mod; mod = mod->link)
			add_reply_string_format(c, "%30.30s  %s [Status: %s]\r\n", mod->name, mod->info->desc,
				mod->flags.running == 1 ? "Running" :
					(mod->flags.declined == 1 ? "Declined" : "Failed"));
	} else if (!strcasecmp(c->argv[1], "applications")) {
		struct application *app = get_application_list_head();

		for (; app; app = app->link)
			add_reply_string_format(c, "%30.30s  %s [Module: %s]\r\n",
				app->name, app->desc, app->mod->name);
	} else if (!strcasecmp(c->argv[1], "queues")) {
		dlist_iter_t iter, iter2;
		dlist_node_t node;

		dlist_lock(queues);
		iter = dlist_iter_new(queues, DLIST_START_HEAD);
		while ((node = dlist_next(iter))) {
			struct msgs *msgs = (struct msgs *)dlist_node_value(node);
			dstr appnames = dstr_new_len("", 0);

			dlist_lock(msgs->appouts);
			iter2 = dlist_iter_new(msgs->appouts, DLIST_START_HEAD);
			while ((node = dlist_next(iter2))) {
				struct appout *ao = (struct appout *)dlist_node_value(node);
				const char *appname;

				if ((appname = get_application_name(ao->app))) {
					appnames = dstr_cat(appnames, appname);
					appnames = dstr_cat(appnames, ", ");
				}
			}
			dlist_iter_free(&iter2);
			dlist_unlock(msgs->appouts);
			add_reply_string_format(c, "%30.30s  %s\r\n", msgs->name,
				dstr_length(appnames) == 0 ? appnames : dstr_range(appnames, 0, -3));
			dstr_free(appnames);
		}
		dlist_iter_free(&iter);
		dlist_unlock(queues);
	} else
		add_reply_error_format(c, "unknown property '%s'", c->argv[1]);
	add_reply_string(c, "\r\n", 2);
}

static void module_command(client c) {
	if (!strcasecmp(c->argv[1], "load")) {
		/* FIXME */
		if (module_load("/var/lib/xcb", c->argv[2]) != MODULE_LOAD_SUCCESS)
			add_reply_error_format(c, "module '%s' loaded NOT OK", c->argv[2]);
		else
			add_reply_string_format(c, "module '%s' loaded OK\r\n", c->argv[2]);
	} else if (!strcasecmp(c->argv[1], "unload")) {
		if (module_unload(c->argv[2]) != MODULE_LOAD_SUCCESS)
			add_reply_error_format(c, "module '%s' unloaded NOT OK", c->argv[2]);
		else
			add_reply_string_format(c, "module '%s' unloaded OK\r\n", c->argv[2]);
	} else if (!strcasecmp(c->argv[1], "reload")) {
		if (module_reload(c->argv[2]) != MODULE_RELOAD_SUCCESS)
			add_reply_error_format(c, "module '%s' reloaded NOT OK", c->argv[2]);
		else
			add_reply_string_format(c, "module '%s' reloaded OK\r\n", c->argv[2]);
	} else
		add_reply_error_format(c, "unknown action '%s'", c->argv[1]);
	add_reply_string(c, "\r\n", 2);
}

/* FIXME */
static void monitor_command(client c) {
	if (!strcasecmp(c->argv[1], "on")) {
		dlist_rwlock_wrlock(monitors);
		if (dlist_find(monitors, c) == NULL)
			dlist_insert_tail(monitors, c);
		dlist_rwlock_unlock(monitors);
	} else if (!strcasecmp(c->argv[1], "off")) {
		remove_from_monitors(c);
		add_reply_string(c, "\r\n", 2);
	} else
		add_reply_error_format(c, "unknown action '%s'\r\n", c->argv[1]);
}

/* FIXME */
static void database_command(client c) {
	db_iterator_t *it;
	int i;

	if (!persistence) {
		add_reply_error(c, "database not open\r\n");
		return;
	}
	if (!strcasecmp(c->argv[1], "head")) {
		it = db_iterator_create(db, db_ro);
		db_iterator_seek_to_first(it);
		if (!db_iterator_valid(it)) {
			add_reply_string(c, "-1\r\n\r\n", 6);
			return;
		}
		for (i = 0; i < 10; ++i) {
			const char *key, *value;
			size_t klen, vlen;

			key   = db_iterator_key(it, &klen);
			value = db_iterator_key(it, &vlen);
			add_reply_string(c, key, klen);
			add_reply_string(c, ",", 1);
			add_reply_string(c, value, vlen);
			add_reply_string(c, "\r\n", 2);
			db_iterator_next(it);
			if (!db_iterator_valid(it))
				break;
		}
		db_iterator_destroy(&it);
	} else if (!strcasecmp(c->argv[1], "tail")) {
		dlist_t dlist = dlist_new(NULL, vfree2);
		dlist_iter_t iter;
		dlist_node_t node;

		it = db_iterator_create(db, db_ro);
		db_iterator_seek_to_last(it);
		if (!db_iterator_valid(it)) {
			add_reply_string(c, "-1\r\n\r\n", 6);
			return;
		}
		for (i = 0; i < 10; ++i) {
			const char *key, *value;
			size_t klen, vlen;
			dstr ds;

			key   = db_iterator_key(it, &klen);
			value = db_iterator_key(it, &vlen);
			ds = dstr_new_len(key, klen);
			ds = dstr_cat(ds, ",");
			ds = dstr_cat_len(ds, value, vlen);
			dlist_insert_head(dlist, ds);
			db_iterator_prev(it);
			if (!db_iterator_valid(it))
				break;
		}
		iter = dlist_iter_new(dlist, DLIST_START_HEAD);
		while ((node = dlist_next(iter))) {
			dstr ds = (dstr)dlist_node_value(node);

			add_reply_string(c, ds, dstr_length(ds));
			add_reply_string(c, "\r\n", 2);
		}
		dlist_iter_free(&iter);
		db_iterator_destroy(&it);
		dlist_free(&dlist);
	} else if (!strcasecmp(c->argv[1], "put")) {
		if (c->argc >= 4) {
			char *dberr = NULL;

			db_put(db, db_wo, c->argv[2], dstr_length(c->argv[2]),
				c->argv[3], dstr_length(c->argv[3]), &dberr);
			if (dberr) {
				add_reply_error_format(c, "database put: %s", dberr);
				db_free(dberr);
			} else
				add_reply_string(c, "OK\r\n", 4);
		}
	} else if (!strcasecmp(c->argv[1], "delete")) {
		if (c->argc >= 3) {
			char *dberr = NULL;

			db_delete(db, db_wo, c->argv[2], dstr_length(c->argv[2]), &dberr);
			if (dberr) {
				add_reply_error_format(c, "database delete: %s", dberr);
				db_free(dberr);
			} else
				add_reply_string(c, "OK\r\n", 4);
		}
	} else if (!strcasecmp(c->argv[1], "compact")) {
		db_compact_range(db, NULL, 0, NULL, 0);
		add_reply_string(c, "OK\r\n", 4);
	} else if (!strcasecmp(c->argv[1], "props")) {
		if (c->argc >= 3) {
			char buf[64], *prop;

			if (!strcasecmp(c->argv[2], "stats") || !strcasecmp(c->argv[2], "sstables"))
				snprintf(buf, sizeof buf, "leveldb.%s", c->argv[2]);
			else if (!strcmp(c->argv[2], "0") || !strcmp(c->argv[2], "1") ||
				!strcmp(c->argv[2], "2") || !strcmp(c->argv[2], "3") ||
				!strcmp(c->argv[2], "4") || !strcmp(c->argv[2], "5") ||
				!strcmp(c->argv[2], "6"))
				snprintf(buf, sizeof buf, "leveldb.num-files-at-level%s", c->argv[2]);
			else {
				add_reply_error_format(c, "unknown property '%s'\r\n", c->argv[2]);
				return;
			}
			prop = db_property_value(db, buf);
			add_reply_string(c, prop, strlen(prop));
			add_reply_string(c, "\r\n", 2);
			db_free(prop);
		}
	} else
		add_reply_error_format(c, "unknown action '%s'", c->argv[1]);
	add_reply_string(c, "\r\n", 2);
}

static void shutdown_command(client c) {
	if (prepare_for_shutdown() == 0)
		exit(0);
	add_reply_error(c, "errors trying to shutdown the server\r\n");
}

