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
#include <dirent.h>
#include <errno.h>
#ifdef __linux__
#define CONFIG_HAVE_BACKTRACE 1
#define CONFIG_HAVE_EPOLL     1
#include <execinfo.h>
#endif
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
/* FIXME */
#include "macros.h"
#undef MIN
#undef MAX
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
#include "pgmsock.h"
#include "db.h"
#include "utilities.h"
#include "basics.h"
#include "commons.h"

/* FIXME */
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
event_loop el;

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

/* FIXME */
static table_t cmds;
static struct cmd commands[] = {
	{"help",	help_command,		"Display this text",			1},
	{"?",		help_command,		"Synonym for 'help'",			1},
	{"config",	config_command,		"Get or set configurations",		-3},
	{"show",	show_command,		"Show modules, applictions or queues",	2},
	{"module",	module_command,		"Load, unload or reload module",	3},
	{"monitor",	monitor_command,	"Monitor on or off",			2},
	{"database",	database_command,	"Database operations",			-1},
	{"shutdown",	shutdown_command,	"Shut down xcb-wk2",			1},
	{"quit",	NULL,			"Quit connecting to xcb-wk2",		1}
};
static struct config *cfg;
static pthread_mutex_t cfg_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static const char *cfg_path;
static dlist_t queues;
static dlist_t clients;
static dlist_t monitors;
static thrpool_t tp;
static struct pgm_cfg *pgm_send_cfg;
static pgm_sock_t *pgm_sender = NULL;
static dlist_t filter;
static int persistence = 0;
static db_t *db;
static db_options_t *db_o;
static db_writeoptions_t *db_wo;
static db_writebatch_t *db_wb;
static pthread_mutex_t wb_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static int dirty = 0;
static dlist_t pgm_recv_cfgs;
static dlist_t pgm_receivers;
static char neterr[256];
static int tcpsock = -1;
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
		"    xcb-wk2 crashed by signal: %d\n--- STACK TRACE", sig);
	close_logger();
	if ((fd = open("/var/log/xcb/xcb-wk2.log", O_APPEND | O_CREAT | O_WRONLY, 0644)) == -1)
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
	/* FIXME */
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
	fprintf(stderr, "Usage: ./xcb-wk2 [-f] path/to/xcb-wk2.conf\n");
	fprintf(stderr, "       ./xcb-wk2 -h or --help\n");
	exit(1);
}

/* FIXME */
void msgfree(void *value) {
	msg_decr((struct msg *)value);
}

/* FIXME */
static void init_pgm_send_cfg(struct pgm_cfg *pgm_send_cfg) {
	char *cat = category_browse(cfg, NULL);

	while (cat) {
		if (!strcasecmp(cat, "pgm_sender")) {
			struct variable *var = variable_browse(cfg, cat);

			while (var) {
				if (!strcasecmp(var->name, "network")) {
					if (strcmp(var->value, ""))
						pgm_send_cfg->network = var->value;
				} else if (!strcasecmp(var->name, "port")) {
					if (strcmp(var->value, ""))
						pgm_send_cfg->port = atoi(var->value);
				} else
					xcb_log(XCB_LOG_WARNING, "Unknown variable '%s' in category '%s'"
						" of xcb-wk2.conf", var->name, cat);
				var = var->next;
			}
		}
		cat = category_browse(cfg, cat);
	}
}

/* FIXME */
static int prepare_for_shutdown(void) {
	/* indices */
	dstr res = dstr_new("INDICES|");
	dstr ip = getipv4();

	xcb_log(XCB_LOG_WARNING, "User requested shutdown...");
	res = dstr_cat(res, ip);
	res = dstr_cat(res, "|");
	out2rmp(res);
	dstr_free(ip);
	dstr_free(res);
	if (persistence) {
		pthread_mutex_lock(&wb_lock);
		db_close(&db);
		pthread_mutex_unlock(&wb_lock);
	}
	if (tcpsock != -1)
		close(tcpsock);
	xcb_log(XCB_LOG_WARNING, "xcb-wk2 is now ready to exit, bye bye...");
	close_logger();
	return 0;
}

static int server_cron(event_loop el, unsigned long id, void *data) {
	dlist_iter_t iter;
	dlist_node_t node;
	NOT_USED(el);
	NOT_USED(id);
	NOT_USED(data);

	if (log_reload) {
		close_logger();
		if (init_logger("/var/log/xcb/xcb-wk2.log", __LOG_DEBUG) == 0) {
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
		dstr res, ip = getipv4();
		dlist_iter_t iter2;

		/* heartbeat */
		dlist_lock(clients);
		if (dlist_length(clients) > 0) {
			res = dstr_new("HEARTBEAT|");
			res = dstr_cat(res, ip);
			res = dstr_cat(res, "\r\n");
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
			dstr_free(res);
		}
		dlist_unlock(clients);
		/* indices */
		res = dstr_new("INDICES|");
		res = dstr_cat(res, ip);
		res = dstr_cat(res, "|");
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
					dstr res2 = dstr_new("INDEX|");
					dstr tmp = dstr_new(appname);

					STR2UPPER(tmp);
					res = dstr_cat(res, tmp);
					res = dstr_cat(res, ",");
					res2 = dstr_cat(res2, tmp);
					res2 = dstr_cat(res2, "|");
					res2 = dstr_cat(res2, get_application_format(ao->app));
					out2rmp(res2);
					dstr_free(tmp);
					dstr_free(res2);
				}
			}
			dlist_iter_free(&iter2);
			dlist_unlock(msgs->appouts);
		}
		dlist_iter_free(&iter);
		dlist_unlock(queues);
		if (res[dstr_length(res) - 1] == ',')
			res = dstr_range(res, 0, -2);
		out2rmp(res);
		dstr_free(ip);
		dstr_free(res);
	}
	++cronloops;
	return 100;
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

/* FIXME */
static void init_pgm_recv_cfg(char *cat, struct pgm_cfg *pgm_recv_cfg) {
	struct variable *var = variable_browse(cfg, cat);

	while (var) {
		if (!strcasecmp(var->name, "network")) {
			if (strcmp(var->value, ""))
				pgm_recv_cfg->network = var->value;
		} else if (!strcasecmp(var->name, "port")) {
			if (strcmp(var->value, ""))
				pgm_recv_cfg->port = atoi(var->value);
		} else
			xcb_log(XCB_LOG_WARNING, "Unknown variable '%s' in category '%s'"
				" of xcb-wk2.conf", var->name, cat);
		var = var->next;
	}
}

static int on_msgv(struct pgm_msgv_t *msgv, size_t len) {
	int i = 0;

	do {
		int j, aqdu_len = 0;
		struct pgm_sk_buff_t* pskb = msgv[i].msgv_skb[0];
		Quote *quote;
		struct msg *msg;

		for (j = 0; j < msgv[i].msgv_len; ++j)
			aqdu_len += msgv[i].msgv_skb[j]->len;
		++i;
		len -= aqdu_len;
		quote = (Quote *)pskb->data;
		if (quote->thyquote.m_nLen == sizeof (THYQuote)) {
			dlist_iter_t iter;
			dlist_node_t node;

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
			if (node == NULL)
				continue;
			if (NEW0(msg) == NULL)
				continue;
			if ((msg->data = ALLOC(sizeof *quote)) == NULL) {
				FREEMSG(msg);
				continue;
			}
			memcpy(msg->data, quote, sizeof *quote);
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
			/* FIXME */
			if (persistence) {
				char key[256], value[1024];

				snprintf(key, sizeof key, "%d,%d,%s", quote->thyquote.m_nTime,
					quote->m_nMSec, quote->thyquote.m_cHYDM);
				snprintf(value, sizeof value, "%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
					"%d,%.2f,%d,%d,%.2f,%d,%.2f,%d",
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
				pthread_mutex_lock(&wb_lock);
				db_writebatch_put(db_wb, key, value);
				pthread_mutex_unlock(&wb_lock);
				dirty = 1;
			}
		/* plain old string, for testing with nc only */
		} else {
			if (NEW0(msg) == NULL)
				continue;
			if ((msg->data = mem_strndup(pskb->data, pskb->len)) == NULL) {
				FREEMSG(msg);
				continue;
			}
			msg->refcount = 1;
			xcb_log(XCB_LOG_DEBUG, "Data '%s' received", msg->data);
			pthread_mutex_lock(&default_msgs.lock);
			if (default_msgs.first == NULL)
				default_msgs.last = default_msgs.first = msg;
			else {
				default_msgs.last->link = msg;
				default_msgs.last = msg;
			}
			pthread_cond_signal(&default_msgs.cond);
			pthread_mutex_unlock(&default_msgs.lock);
		}
		/* FIXME */
		if (shut_down)
			break;
	} while (len > 0);
	return 0;
}

/* receiver thread */
static void *receiver_thread(void *data) {
	pgm_sock_t *pgm_receiver = (pgm_sock_t *)data;
	/* FIXME */
	int iov_len = 20;
	struct pgm_msgv_t msgv[iov_len];
#ifdef CONFIG_HAVE_EPOLL
	int efd, ev_len = 1;
	/* wait for maximum 1 event */
	struct epoll_event events[ev_len];

	/* FIXME */
	if ((efd = epoll_create(20)) == -1) {
		xcb_log(XCB_LOG_WARNING, "Opening epoll fd: %s", strerror(errno));
		return NULL;
	}
	if (pgm_epoll_ctl(pgm_receiver, efd, EPOLL_CTL_ADD, EPOLLIN) == -1) {
		xcb_log(XCB_LOG_WARNING, "Registering socket on epoll fd '%d': %s", efd, strerror(errno));
		return NULL;
	}
#else
	fd_set readfds;
	int nfds = 0;

#endif
	for (;;) {
		size_t len;
		pgm_error_t *pgm_err = NULL;
		int status;
		struct timeval tv;
#ifdef CONFIG_HAVE_EPOLL
		int timeout;
#endif

		status = pgm_recvmsgv(pgm_receiver, msgv, NELEMS(msgv), 0, &len, &pgm_err);
		switch (status) {
		case PGM_IO_STATUS_NORMAL:
			on_msgv(msgv, len);
			break;
		case PGM_IO_STATUS_TIMER_PENDING:
			{
				socklen_t optlen = sizeof tv;

				pgm_getsockopt(pgm_receiver, IPPROTO_PGM, PGM_TIME_REMAIN, &tv, &optlen);
			}
			goto block;
		case PGM_IO_STATUS_RATE_LIMITED:
			{
				socklen_t optlen = sizeof tv;

				pgm_getsockopt(pgm_receiver, IPPROTO_PGM, PGM_RATE_REMAIN, &tv, &optlen);
			}
			/* fall through */
		case PGM_IO_STATUS_WOULD_BLOCK:

block:
#ifdef CONFIG_HAVE_EPOLL
			timeout = status == PGM_IO_STATUS_WOULD_BLOCK
				? -1 : (tv.tv_sec * 1000 + tv.tv_usec / 1000);
			epoll_wait(efd, events, NELEMS(events), timeout);
#else
			FD_ZERO(&readfds);
			pgm_select_info(pgm_receiver, &readfds, NULL, &nfds);
			select(nfds, &readfds, NULL, NULL, status == PGM_IO_STATUS_RATE_LIMITED ? &tv : NULL);
#endif
			break;
		case PGM_IO_STATUS_RESET:
			{
				struct pgm_sk_buff_t* pskb = msgv[0].msgv_skb[0];

				pgm_free_skb(pskb);
			}
		default:
			if (pgm_err) {
				xcb_log(XCB_LOG_ERROR, "Receiving data: %s", pgm_err->message);
				pgm_error_free(pgm_err);
				pgm_err = NULL;
			}
			if (status == PGM_IO_STATUS_ERROR)
				break;
		}
		if (shut_down)
			break;
	}
#ifdef CONFIG_HAVE_EPOLL
	close(efd);
#endif
	return NULL;
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
		int status;

		/* for testing */
		dlist_rwlock_rdlock(monitors);
		if (dlist_length(monitors) > 0) {
			dstr ds = dstr_new("TX '");
			dlist_iter_t iter = dlist_iter_new(monitors, DLIST_START_HEAD);
			dlist_node_t node;

			ds = dstr_cat(ds, res);
			ds = dstr_cat(ds, "'\r\n");
			while ((node = dlist_next(iter))) {
				client c = (client)dlist_node_value(node);

				pthread_spin_lock(&c->lock);
				if (c->flags & CLIENT_CLOSE_ASAP) {
					pthread_spin_unlock(&c->lock);
					continue;
				}
				if (net_try_write(c->fd, ds, dstr_length(ds), 10, NET_NONBLOCK) == -1) {
					xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
						c, strerror(errno));
					if (++c->eagcount >= 10)
						client_free_async(c);
				} else if (c->eagcount)
					c->eagcount = 0;
				pthread_spin_unlock(&c->lock);
			}
			dlist_iter_free(&iter);
			dstr_free(ds);
		}
		dlist_rwlock_unlock(monitors);
		if ((status = pgm_send(pgm_sender, res, strlen(res), NULL)) != PGM_IO_STATUS_NORMAL)
			xcb_log(XCB_LOG_WARNING, "Sending data failed");
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
	pgm_error_t *pgm_err = NULL;
	char *cat;

	/* FIXME */
	signal(SIGPIPE, SIG_IGN);
	setup_signal_handlers();
	cmds = table_new(cmpstr, hashmurmur2, NULL, NULL);
	ncmds = sizeof commands / sizeof (struct cmd);
	for (i = 0; i < ncmds; ++i) {
		struct cmd *cmd = commands + i;

		table_insert(cmds, cmd->name, cmd);
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
	if (init_logger("/var/log/xcb/xcb-wk2.log", __LOG_DEBUG) == -1) {
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
	default_msgs.appouts = dlist_new(NULL, NULL);
	queues = dlist_new(NULL, NULL);
	dlist_insert_head(queues, &default_msgs);
	clients_to_close = dlist_new(NULL, NULL);
	clients = dlist_new(NULL, NULL);
	monitors = dlist_new(NULL, NULL);
	tp = thrpool_new(16, 512, 200, NULL);
	if (!pgm_init(&pgm_err)) {
		xcb_log(XCB_LOG_ERROR, "Error starting PGM engine: %s", pgm_err->message);
		pgm_error_free(pgm_err);
		goto err;
	}
	/* FIXME */
	if (NEW(pgm_send_cfg) == NULL) {
		xcb_log(XCB_LOG_ERROR, "Error allocating memory for PGM cfg");
		goto err;
	}
	pgm_send_cfg->network = NULL;
	pgm_send_cfg->port    = 0;
	init_pgm_send_cfg(pgm_send_cfg);
	if (pgm_send_cfg->network == NULL) {
		xcb_log(XCB_LOG_ERROR, "PGM network can't be NULL");
		goto err;
	}
	if (pgm_send_cfg->port == 0) {
		xcb_log(XCB_LOG_ERROR, "PGM port can't be zero");
		goto err;
	}
	if ((pgm_sender = pgmsock_create(pgm_send_cfg->network, pgm_send_cfg->port, PGMSOCK_SENDER)) == NULL)
		goto err;
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
	}
	/* FIXME */
	pgm_recv_cfgs = dlist_new(NULL, NULL);
	pgm_receivers = dlist_new(NULL, NULL);
	cat = category_browse(cfg, NULL);
	while (cat) {
		if (!strcasecmp(cat, "pgm_receiver")) {
			struct pgm_cfg *pgm_recv_cfg;
			pgm_sock_t *pgm_receiver = NULL;
			pthread_t thread;

			if (NEW(pgm_recv_cfg) == NULL) {
				xcb_log(XCB_LOG_ERROR, "Error allocating memory for PGM cfg");
				goto err;
			}
			pgm_recv_cfg->network = NULL;
			pgm_recv_cfg->port    = 0;
			init_pgm_recv_cfg(cat, pgm_recv_cfg);
			if (pgm_recv_cfg->network == NULL) {
				xcb_log(XCB_LOG_ERROR, "PGM network can't be NULL");
				goto err;
			}
			if (pgm_recv_cfg->port == 0) {
				xcb_log(XCB_LOG_ERROR, "PGM port can't be zero");
				goto err;
			}
			dlist_insert_tail(pgm_recv_cfgs, pgm_recv_cfg);
			if ((pgm_receiver = pgmsock_create(pgm_recv_cfg->network, pgm_recv_cfg->port,
				PGMSOCK_RECEIVER)) == NULL)
				goto err;
			dlist_insert_tail(pgm_receivers, pgm_receiver);
			if (pthread_create(&thread, NULL, receiver_thread, pgm_receiver) != 0) {
				xcb_log(XCB_LOG_ERROR, "Error initializing receiver thread");
				goto err;
			}
		}
		cat = category_browse(cfg, cat);
	}
	if ((tmp = variable_retrieve(cfg, "general", "tcp_port")) && strcmp(tmp, ""))
		if ((tcpsock = net_tcp_server(NULL, atoi(tmp), neterr, sizeof neterr)) == -1) {
			xcb_log(XCB_LOG_ERROR, "Opening port '%s': %s", tmp, neterr);
			goto err;
		}
	if (tcpsock > 0 && create_file_event(el, tcpsock, EVENT_READABLE, tcp_accept_handler, NULL) == -1) {
		xcb_log(XCB_LOG_ERROR, "Unrecoverable error creating tcpsock '%d' file event", tcpsock);
		goto err;
	}
	xcb_log(XCB_LOG_NOTICE, "Server worker started");
	start_event_loop(el, ALL_EVENTS);
	delete_event_loop(el);
	pgm_shutdown();
	return 0;

err:
	close_logger();
	exit(1);
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
	if ((c->cmd = table_get_value(cmds, c->argv[0])) == NULL) {
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
		c->argv = dstr_split_args(c->inbuf, &c->argc);
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
	} else {
		/* heartbeat */
		dstr res = dstr_new("HEARTBEAT|");
		dstr ip = getipv4();

		xcb_log(XCB_LOG_NOTICE, "Accepted %s:%d, client '%p'", cip, cport, c);
		res = dstr_cat(res, ip);
		res = dstr_cat(res, "\r\n");
		pthread_spin_lock(&c->lock);
		if (net_try_write(c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1)
			xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s", c, strerror(errno));
		pthread_spin_unlock(&c->lock);
		dstr_free(ip);
		dstr_free(res);
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
	char *cat;

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
		else if (!strcasecmp(c->argv[2], "receiver") && !strcasecmp(c->argv[3], "network")) {
			int count = 0, found = 0;

			cat = category_browse(cfg, NULL);
			while (cat) {
				if (!strcasecmp(cat, "pgm_receiver")) {
					add_reply_string_format(c, "receiver network %d:%s\r\n",
						++count, variable_retrieve(cfg, cat, "network"));
					found = 1;
				}
				cat = category_browse(cfg, cat);
			}
			if (!found)
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "receiver") && !strcasecmp(c->argv[3], "port")) {
			int count = 0, found = 0;

			cat = category_browse(cfg, NULL);
			while (cat) {
				if (!strcasecmp(cat, "pgm_receiver")) {
					add_reply_string_format(c, "receiver port %d:%s\r\n",
						++count, variable_retrieve(cfg, cat, "port"));
					found = 1;
				}
				cat = category_browse(cfg, cat);
			}
			if (!found)
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "sender") && !strcasecmp(c->argv[3], "network"))
			add_reply_string_format(c, "sender network:%s\r\n",
				variable_retrieve(cfg, "pgm_sender", "network"));
		else if (!strcasecmp(c->argv[2], "sender") && !strcasecmp(c->argv[3], "port"))
			add_reply_string_format(c, "sender port:%s\r\n",
				variable_retrieve(cfg, "pgm_sender", "port"));
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
		} else if (!strcasecmp(c->argv[2], "receiver") && !strcasecmp(c->argv[3], "network") &&
			c->argc >= 5) {
			if (c->argc == 5) {
				category = category_get(cfg, "pgm_receiver");
				if (variable_update(category, "network", c->argv[4]) == 0)
					add_reply_string(c, "OK\r\n", 4);
				else
					add_reply_string(c, "-1\r\n", 4);
			} else {
				int count = 0, found = 0;

				cat = category_browse(cfg, NULL);
				while (cat) {
					if (!strcasecmp(cat, "pgm_receiver") && ++count == atoi(c->argv[4])) {
						category = category_get(cfg, cat);
						if (variable_update(category, "network", c->argv[5]) == 0)
							add_reply_string(c, "OK\r\n", 4);
						else
							add_reply_string(c, "-1\r\n", 4);
						found = 1;
						break;
					}
					cat = category_browse(cfg, cat);
				}
				if (!found)
					add_reply_string(c, "-1\r\n", 4);
			}
		} else if (!strcasecmp(c->argv[2], "receiver") && !strcasecmp(c->argv[3], "port") &&
			c->argc >= 5) {
			if (c->argc == 5) {
				category = category_get(cfg, "pgm_receiver");
				if (variable_update(category, "port", c->argv[4]) == 0)
					add_reply_string(c, "OK\r\n", 4);
				else
					add_reply_string(c, "-1\r\n", 4);
			} else {
				int count = 0, found = 0;

				cat = category_browse(cfg, NULL);
				while (cat) {
					if (!strcasecmp(cat, "pgm_receiver") && ++count == atoi(c->argv[4])) {
						category = category_get(cfg, cat);
						if (variable_update(category, "port", c->argv[5]) == 0)
							add_reply_string(c, "OK\r\n", 4);
						else
							add_reply_string(c, "-1\r\n", 4);
						found = 1;
						break;
					}
					cat = category_browse(cfg, cat);
				}
				if (!found)
					add_reply_string(c, "-1\r\n", 4);
			}
		} else if (!strcasecmp(c->argv[2], "sender") && !strcasecmp(c->argv[3], "network") &&
			c->argc >= 5) {
			category = category_get(cfg, "pgm_sender");
			if (variable_update(category, "network", c->argv[4]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
		} else if (!strcasecmp(c->argv[2], "sender") && !strcasecmp(c->argv[3], "port") &&
			c->argc >= 5) {
			category = category_get(cfg, "pgm_sender");
			if (variable_update(category, "port", c->argv[4]) == 0)
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

static void database_command(client c) {
	/* FIXME */
	add_reply_error(c, "this command has not been implemented\r\n");
}

static void shutdown_command(client c) {
	if (prepare_for_shutdown() == 0)
		exit(0);
	add_reply_error(c, "errors trying to shutdown the server\r\n");
}

