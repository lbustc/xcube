/*
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*
 * tailored by xiaoyem
 */

#include "fmacros.h"
#include <alloca.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include "macros.h"
#include "mem.h"
#include "logger.h"

/* FIXME */
struct logmsg {
	struct logmsg	*next;
	int		level;
	int		lwp;
	int		line;
	char		*date;
	char		*file;
	char		*function;
	char		*message;
};

static struct logmsgs {
	struct logmsg	*first;
	struct logmsg	*last;
	pthread_mutex_t	lock;
} logmsgs = {
	.first = NULL,
	.last  = NULL,
	.lock  = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP,
};
static int logger_inited = 0;
static FILE *logfp = NULL;
static int loglevel = __LOG_NOTICE;
static pthread_t logthread = (pthread_t)-1;
static pthread_cond_t logcond;
static int close_logger_thread = 0;
/* FIXME */
static char *levels[8] = {
	"DEBUG",
	"INFO",
	"NOTICE",
	"WARNING",
	"ERROR",
};

static void logger_print(struct logmsg *logmsg) {
	const int syslog_level_map[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING, LOG_ERR };
	char buf[BUFSIZ];

	if (logfp) {
		snprintf(buf, sizeof buf, "[%s] %s[%d]: %s:%d %s: %s\n",
			logmsg->date,
			levels[logmsg->level],
			logmsg->lwp,
			logmsg->file,
			logmsg->line,
			logmsg->function,
			logmsg->message);
		fputs(buf, logfp);
		fflush(logfp);
	} else {
		snprintf(buf, sizeof buf, "%s[%d]: %s:%d in %s: %s\n",
			levels[logmsg->level],
			logmsg->lwp,
			logmsg->file,
			logmsg->line,
			logmsg->function,
			logmsg->message);
		syslog(syslog_level_map[logmsg->level], "%s", buf);
	}
}

static void free_logmsg(struct logmsg *logmsg) {
	/* FIXME */
	if (logmsg) {
		FREE(logmsg->message);
		FREE(logmsg->function);
		FREE(logmsg->file);
		FREE(logmsg->date);
		FREE(logmsg);
	}
}

/* actual logging thread */
static void *logger_thread(void *data) {
	struct logmsg *next = NULL, *msg = NULL;
	NOT_USED(data);

	for (;;) {
		pthread_mutex_lock(&logmsgs.lock);
		/* test whether it is empty */
		if (logmsgs.first == NULL) {
			if (close_logger_thread)
				break;
			else
				pthread_cond_wait(&logcond, &logmsgs.lock);
		}
		next = logmsgs.first;
		logmsgs.first = NULL;
		logmsgs.last  = NULL;
		pthread_mutex_unlock(&logmsgs.lock);
		while ((msg = next)) {
			next = msg->next;
			logger_print(msg);
			free_logmsg(msg);
		}
		if (close_logger_thread)
			break;
	}
	return NULL;
}

int init_logger(const char *path, int level) {
	if (logger_inited)
		return 0;
	if (logfp) {
		fclose(logfp);
		logfp = NULL;
	} else
		closelog();
	if (path) {
		char *p, *tmp = strdupa(path), *fullpath = alloca(strlen(path) + 1);
		int count = 0, pcount = 0, i;
		char **pieces;

		for (p = tmp; *p; ++p)
			if (*p == '/')
				++count;
		pieces = alloca(count * sizeof *pieces);
		for (p = tmp; *p; ++p)
			if (*p == '/') {
				*p = '\0';
				pieces[pcount++] = p + 1;
			}
		*fullpath = '\0';
		for (i = 0; i < pcount - 1; ++i) {
			strcat(fullpath, "/");
			strcat(fullpath, pieces[i]);
			/* FIXME: hard-coded mode */
			if (mkdir(fullpath, 0777) != 0 && errno != EEXIST)
				return -1;
		}
		logfp = fopen(path, "a");
	}
	/* FIXME */
	if (logfp == NULL)
		openlog("xcb", LOG_PID, LOG_USER);
	if (level >= __LOG_DEBUG && level <= __LOG_ERROR)
		loglevel = level;
	close_logger_thread = 0;
	pthread_cond_init(&logcond, NULL);
	if (pthread_create(&logthread, NULL, logger_thread, NULL) != 0) {
		pthread_cond_destroy(&logcond);
		return -1;
	}
	logger_inited = 1;
	return 0;
}

void close_logger(void) {
	if (!logger_inited)
		return;
	pthread_mutex_lock(&logmsgs.lock);
	close_logger_thread = 1;
	pthread_cond_signal(&logcond);
	pthread_mutex_unlock(&logmsgs.lock);
	if (logthread != (pthread_t)-1)
		pthread_join(logthread, NULL);
	if (logfp) {
		fclose(logfp);
		logfp = NULL;
	} else
		closelog();
	logger_inited = 0;
}

void xcb_log(int level, const char *file, int line, const char *function, const char *fmt, ...) {
	struct logmsg *msg = NULL;
	struct timeval tv;
	char datestr[64];
	int off;
	va_list ap;
	char buf[8192];

	if (level < loglevel)
		return;
	if (NEW(msg) == NULL)
		return;
	/* FIXME: looks funky */
	msg->next  = NULL;
	msg->level = level;
	msg->lwp   = syscall(SYS_gettid);
	msg->line  = line;
	gettimeofday(&tv, NULL);
	off = strftime(datestr, sizeof datestr, "%b %e %T.", localtime(&tv.tv_sec));
	snprintf(datestr + off, sizeof datestr - off, "%06d", (int)tv.tv_usec);
	if ((msg->date = ALLOC(strlen(datestr) + 1)) == NULL)
		goto err;
	memcpy(msg->date, datestr, strlen(datestr));
	msg->date[strlen(datestr)] = '\0';
	if ((msg->file = ALLOC(strlen(file) + 1)) == NULL)
		goto err;
	memcpy(msg->file, file, strlen(file));
	msg->file[strlen(file)] = '\0';
	if ((msg->function = ALLOC(strlen(function) + 1)) == NULL)
		goto err;
	memcpy(msg->function, function, strlen(function));
	msg->function[strlen(function)] = '\0';
	va_start(ap, fmt);
	/* FIXME */
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if ((msg->message = ALLOC(strlen(buf) + 1)) == NULL)
		goto err;
	memcpy(msg->message, buf, strlen(buf));
	msg->message[strlen(buf)] = '\0';
	if (logthread != (pthread_t)-1) {
		pthread_mutex_lock(&logmsgs.lock);
		if (logmsgs.first == NULL)
			logmsgs.last = logmsgs.first = msg;
		else {
			logmsgs.last->next = msg;
			logmsgs.last = msg;
		}
		pthread_cond_signal(&logcond);
		pthread_mutex_unlock(&logmsgs.lock);
	} else {
		logger_print(msg);
		free_logmsg(msg);
	}
	return;

err:
	free_logmsg(msg);
}

void set_logger_level(int level) {
	if (level >= __LOG_DEBUG && level <= __LOG_ERROR)
		loglevel = level;
}

inline int get_logger_level(void) {
	return loglevel;
}

