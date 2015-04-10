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
#include <arpa/inet.h>
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
#include "net.h"
#include "event.h"
#include "thrpool.h"
#include "pgmsock.h"
#include "utilities.h"
#include "basics.h"
#include "commons.h"

/* FIXME */
struct sms {
	int32_t	qsec, sec, msec;
};

/* FIXME */
dlist_t clients_to_close;
event_loop el;

/* FIXME */
void client_free(client c);
static void tcp_accept_handler(event_loop el, int fd, int mask, void *data);
static void help_command(client c);
static void config_command(client c);
static void monitor_command(client c);
static void shutdown_command(client c);

/* FIXME */
static table_t cmds;
static struct cmd commands[] = {
	{"help",	help_command,		"Display this text",			1},
	{"?",		help_command,		"Synonym for 'help'",			1},
	{"config",	config_command,		"Get or set configurations",		-3},
	{"monitor",	monitor_command,	"Monitor on or off",			2},
	{"shutdown",	shutdown_command,	"Shut down xcb-dp2",			1},
	{"quit",	NULL,			"Quit connecting to xcb-dp2",		1}
};
static struct config *cfg;
static pthread_mutex_t cfg_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;
static const char *cfg_path;
static int addms = 0;
static table_t times;
static dlist_t clients;
static dlist_t monitors;
static thrpool_t tp;
static struct pgm_cfg *pgm_send_cfg;
static pgm_sock_t *pgm_sender = NULL;
static char neterr[256];
static int udpsock = -1;
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
		"    xcb-dp2 crashed by signal: %d\n--- STACK TRACE", sig);
	close_logger();
	if ((fd = open("/var/log/xcb/xcb-dp2.log", O_APPEND | O_CREAT | O_WRONLY, 0644)) == -1)
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
	fprintf(stderr, "Usage: ./xcb-dp2 [-f] path/to/xcb-dp2.conf\n");
	fprintf(stderr, "       ./xcb-dp2 -h or --help\n");
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
static void msgfree(void *value) {
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
						" of xcb-dp2.conf", var->name, cat);
				var = var->next;
			}
		}
		cat = category_browse(cfg, cat);
	}
}

/* FIXME */
static int prepare_for_shutdown(void) {
	xcb_log(XCB_LOG_WARNING, "User requested shutdown...");
	if (udpsock != -1)
		close(udpsock);
	if (tcpsock != -1)
		close(tcpsock);
	xcb_log(XCB_LOG_WARNING, "xcb-dp2 is now ready to exit, bye bye...");
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
		if (init_logger("/var/log/xcb/xcb-dp2.log", __LOG_DEBUG) == 0) {
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
	if (cronloops % 200 == 0) {
		char meme[] = "SU OT GNOLEB ERA ESAB RUOY LLA";
		int status;

		/* heartbeat */
		dlist_lock(clients);
		if (dlist_length(clients) > 0) {
			dstr res = dstr_new("HEARTBEAT|");
			dstr ip = getipv4();

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
			dstr_free(ip);
			dstr_free(res);
		}
		dlist_unlock(clients);
		/* FIXME: trying to lower the high CPU load while idle */
		if ((status = pgm_send(pgm_sender, meme, sizeof meme, NULL)) != PGM_IO_STATUS_NORMAL)
			xcb_log(XCB_LOG_WARNING, "Communication test failed");
	}
	++cronloops;
	return 100;
}

static int send_quote(void *data, void *data2) {
	struct msg *msg = (struct msg *)data;
	Quote *quote;
	int status;
	NOT_USED(data2);

	quote = (Quote *)msg->data;
	if (quote->thyquote.m_nLen == sizeof (THYQuote)) {
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
		/* for testing */
		dlist_rwlock_rdlock(monitors);
		if (dlist_length(monitors) > 0) {
			char res[512];
			dlist_iter_t iter = dlist_iter_new(monitors, DLIST_START_HEAD);
			dlist_node_t node;

			snprintf(res, sizeof res, "TX '%d,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
				"%d,%.2f,%d,%d,%.2f,%d,%.2f,%d'\r\n",
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
	}
	/* FIXME */
	if ((status = pgm_send(pgm_sender, msg->data, sizeof (Quote), NULL)) != PGM_IO_STATUS_NORMAL)
		xcb_log(XCB_LOG_WARNING, "Sending data failed");
	msg_decr(msg);
	return 0;
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
			int tlen;

			quote->thyquote.m_cJYS[sizeof quote->thyquote.m_cJYS - 1] = '\0';
			quote->thyquote.m_cHYDM[sizeof quote->thyquote.m_cHYDM - 1] = '\0';
			quote->m_nMSec = 0;
			/* for testing */
			dlist_rwlock_rdlock(monitors);
			if (dlist_length(monitors) > 0) {
				char res[512];
				dlist_iter_t iter = dlist_iter_new(monitors, DLIST_START_HEAD);
				dlist_node_t node;

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
		}
		if (NEW0(msg) == NULL) {
			FREE(buf);
			return;
		}
		msg->data     = buf;
		msg->refcount = 1;
		thrpool_queue(tp, send_quote, msg, NULL, msgfree, NULL);
	} else
		FREE(buf);
}

int main(int argc, char **argv) {
	int ncmds, i;
	const char *tmp;
	pgm_error_t *pgm_err = NULL;

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
	if (init_logger("/var/log/xcb/xcb-dp2.log", __LOG_DEBUG) == -1) {
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
	if (udpsock > 0 && create_file_event(el, udpsock, EVENT_READABLE, read_quote, NULL) == -1) {
		xcb_log(XCB_LOG_ERROR, "Unrecoverable error creating udpsock '%d' file event", udpsock);
		goto err;
	}
	if (tcpsock > 0 && create_file_event(el, tcpsock, EVENT_READABLE, tcp_accept_handler, NULL) == -1) {
		xcb_log(XCB_LOG_ERROR, "Unrecoverable error creating tcpsock '%d' file event", tcpsock);
		goto err;
	}
	xcb_log(XCB_LOG_NOTICE, "Server dispatcher started");
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

/* FIXME */
static void config_command(client c) {
	if (!strcasecmp(c->argv[1], "get")) {
		pthread_mutex_lock(&cfg_lock);
		if (!strcasecmp(c->argv[2], "log_level"))
			add_reply_string_format(c, "log_level:%s\r\n",
				variable_retrieve(cfg, "general", "log_level"));
		else if (!strcasecmp(c->argv[2], "udp_port"))
			add_reply_string_format(c, "udp_port:%s\r\n",
				variable_retrieve(cfg, "general", "udp_port"));
		else if (!strcasecmp(c->argv[2], "sender") && !strcasecmp(c->argv[3], "network"))
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
		} else if (!strcasecmp(c->argv[2], "udp_port") && c->argc >= 4) {
			category = category_get(cfg, "general");
			if (variable_update(category, "udp_port", c->argv[3]) == 0)
				add_reply_string(c, "OK\r\n", 4);
			else
				add_reply_string(c, "-1\r\n", 4);
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

static void shutdown_command(client c) {
	if (prepare_for_shutdown() == 0)
		exit(0);
	add_reply_error(c, "errors trying to shutdown the server\r\n");
}

