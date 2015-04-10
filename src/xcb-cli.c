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

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* FIXME */
#include <readline/history.h>
#include <readline/readline.h>
#include "macros.h"
#include "mem.h"
#include "dstr.h"
#include "net.h"

typedef struct command_t {
	char		*name;
	rl_icpfunc_t	*func;
	char		*doc;
} command_t;

/* FIXME */
#define CLIPRINT(str) \
	do { \
		if (rl_inited) { \
			int point = rl_point; \
			char *line = rl_copy_text(0, rl_end); \
			rl_set_prompt(""); \
			rl_replace_line("", 0); \
			rl_redisplay(); \
			fprintf(stdout, "%s\n", str); \
			fflush(stdout); \
			rl_set_prompt(prompt); \
			rl_replace_line(line, 0); \
			rl_point = point; \
			rl_redisplay(); \
			free(line); \
		} \
	} while (0)

/* FIXME */
static dstr ip;
static int port;
static int execute = 0;
static int timestamp = 0;
static int tcpsock = -1;
static char neterr[256];
static int proceed_pipe[2];
static int loop = 1;
static const char *prompt = "xcb*CLI> ";
static int rl_inited = 0;
static int inpos = 0;
static char inbuf[4 * 1024 * 1024];

static int com_help(char *arg);
static int com_quit(char *arg);

command_t commands[] = {
	{ "help",	com_help,	"Display this text"  },
	{ "?",		com_help,	"Synonym for 'help'" },
	{ "quit",	com_quit,	"Quit using xcb-cli" },
	{ NULL,		NULL,		NULL                 }
};

static char *command_generator(const char *text, int state) {
	static int i, len;
	char *name;

	if (state == 0) {
		i = 0;
		len = strlen(text);
	}
	while ((name = commands[i].name)) {
		++i;
		if (!strncmp(name, text, len))
			return mem_strdup(name);
	}
	return NULL;
}

static char **cli_completion(const char *text, int start, int end) {
	char **matches = NULL;
	NOT_USED(end);

	if (start == 0)
		matches = rl_completion_matches(text, command_generator);
	return matches;
}

static command_t *find_command(char *name) {
	int i;

	for (i = 0; commands[i].name; ++i)
		if (!strcmp(commands[i].name, name))
			return &commands[i];
	return NULL;
}

/* FIXME */
static void usage(void) {
	fprintf(stderr,
		"Usage: xcb-cli [OPTION]...\n"
		"  -h <hostname> Server hostname (default: 127.0.0.1)\n"
		"  -p <port>     Server port (default: 33330)\n"
		"  -x            Execute a command and quit\n"
		"  -t            Print timestamps\n"
		"  -?            Output this help and exit\n");
	exit(1);
}

static void *recv_thread(void *data) {
	NOT_USED(data);

	while (loop) {
		struct pollfd rfd[1];
		char buf[256];
		int nread;

		rfd[0].fd     = tcpsock;
		rfd[0].events = POLLIN;
		if (poll(rfd, 1, -1) == -1) {
			if (execute) {
				fprintf(stderr, "Reading from server: %s\n", strerror(errno));
				exit(1);
			} else {
				snprintf(buf, sizeof buf, "Reading from server: %s", strerror(errno));
				CLIPRINT(buf);
				break;
			}
		}
		if ((nread = read(tcpsock, inbuf + inpos, sizeof inbuf - inpos)) == -1) {
			if (errno == EAGAIN || errno == EINTR)
				nread = 0;
			else {
				if (execute) {
					fprintf(stderr, "Reading from server: %s\n", strerror(errno));
					exit(1);
				} else {
					snprintf(buf, sizeof buf, "Reading from server: %s", strerror(errno));
					CLIPRINT(buf);
					break;
				}
			}
		} else if (nread == 0) {
			if (execute) {
				fprintf(stderr, "Server closed connection\n");
				exit(1);
			} else {
				snprintf(buf, sizeof buf, "Server closed connection");
				CLIPRINT(buf);
				break;
			}
		}
		if (nread)
			inpos += nread;
		else
			continue;
		inbuf[inpos] = '\0';
		while (inpos > 0) {
			char *newline;
			size_t len;

			if ((newline = strstr(inbuf, "\r\n")) == NULL) {
				if (inpos == sizeof inbuf - 1) {
					if (execute) {
						fprintf(stderr, "Server error: too big reply\n");
						exit(1);
					} else {
						snprintf(buf, sizeof buf, "Server error: too big reply");
						CLIPRINT(buf);
						inpos = 0;
					}
				}
				break;
			}
			if ((len = newline - inbuf) == 0) {
				const char one = '1';

				if (execute && write(proceed_pipe[1], &one, sizeof(one)) == -1) {
					fprintf(stderr, "Error writing: %s", strerror(errno));
					exit(1);
				}
			} else {
				/* FIXME */
				*newline = '\0';
				if (timestamp) {
					struct timeval tv;
					char datestr[64];
					int off;
					dstr res;

					gettimeofday(&tv, NULL);
					off = strftime(datestr, sizeof datestr, "[%b %e %T.",
						localtime(&tv.tv_sec));
					snprintf(datestr + off, sizeof datestr - off, "%06d]",
						(int)tv.tv_usec);
					res = dstr_new(datestr);
					res = dstr_cat(res, inbuf);
					if (execute) {
						if (strncasecmp(inbuf, "HEARTBEAT", 9) &&
							strncasecmp(inbuf, "INDICES", 7))
							fprintf(stdout, "%s\n", res);
					} else
						CLIPRINT(res);
					dstr_free(res);
				} else {
					if (execute) {
						if (strncasecmp(inbuf, "HEARTBEAT", 9) &&
							strncasecmp(inbuf, "INDICES", 7))
							fprintf(stdout, "%s\n", inbuf);
					} else
						CLIPRINT(inbuf);
				}
			}
			memmove(inbuf, inbuf + len + 2, sizeof inbuf - len - 2);
			inpos -= len + 2;
		}
	}
	close(tcpsock);
	tcpsock = -1;
	return NULL;
}

static void init_readline() {
	rl_readline_name = "xcb-cli";
	rl_attempted_completion_function = cli_completion;
}

static int execute_line(char *line) {
	int i = 0;
	char *word;
	command_t *command;

	while (line[i] && isspace(line[i]))
		++i;
	word = line + i;
	while (line[i] && !isspace(line[i]))
		++i;
	if (line[i])
		line[i++] = '\0';

	if ((command = find_command(word)) == NULL) {
		fprintf(stdout, "%s: No such command for xcb-cli\n", word);
		return -1;
	}

	while (isspace(line[i]))
		++i;
	word = line + i;
	return command->func(word);
}

int main(int argc, char **argv) {
	int opt, count = 1;
	pthread_t thread;

	/* FIXME */
	ip = dstr_new("127.0.0.1");
	port = 33330;
	while ((opt = getopt(argc, argv, "h:p:xt?")) != -1)
		switch (opt) {
		case 'h':
			dstr_free(ip);
			ip = dstr_new(optarg);
			count += 2;
			break;
		case 'p':
			port = atoi(optarg);
			count += 2;
			break;
		case 'x':
			execute = 1;
			count += 1;
			break;
		case 't':
			timestamp = 1;
			count += 1;
			break;
		case '?':
		default:
			usage();
		}
	if ((tcpsock = net_tcp_nonblock_connect(ip, port, neterr, sizeof neterr)) == -1) {
		fprintf(stderr, "Connecting %s:%d: %s\n", ip, port, neterr);
		exit(1);
	}
	if (errno == EINPROGRESS) {
		struct pollfd wfd[1];
		int res, err = 0;
		socklen_t errlen = sizeof err;

		wfd[0].fd     = tcpsock;
		wfd[0].events = POLLOUT;
		/* wait for 5 seconds */
		if ((res = poll(wfd, 1, 5000)) == -1) {
			fprintf(stderr, "Connecting %s:%d: %s\n", ip, port, strerror(errno));
			exit(1);
		} else if (res == 0) {
			errno = ETIMEDOUT;
			fprintf(stderr, "Connecting %s:%d: %s\n", ip, port, strerror(errno));
			exit(1);
		}
		if (getsockopt(tcpsock, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
			fprintf(stderr, "Connecting %s:%d: %s\n", ip, port, strerror(errno));
			exit(1);
		}
		if (err) {
			errno = err;
			fprintf(stderr, "Connecting %s:%d: %s\n", ip, port, strerror(errno));
			exit(1);
		}
	}
	if (execute && pipe(proceed_pipe) != 0) {
		fprintf(stderr, "Error creating pipe: %s\n", strerror(errno));
		exit(1);
	}
	if (execute) {
		argc -= count;
		argv += count;
		if (argc > 0) {
			dstr cmd;
			int i;
			struct pollfd rfd[1];

			if (pthread_create(&thread, NULL, recv_thread, NULL) != 0) {
				fprintf(stderr, "Error initializing receiver thread\n");
				exit(1);
			}
			cmd = dstr_new(argv[0]);
			for (i = 1; i < argc; ++i) {
				cmd = dstr_cat(cmd, " ");
				cmd = dstr_cat(cmd, argv[i]);
			}
			cmd = dstr_cat(cmd, "\r\n");
			net_try_write(tcpsock, cmd, dstr_length(cmd), 100, NET_NONBLOCK);
			/* dstr_free(cmd); */
			rfd[0].fd     = proceed_pipe[0];
			rfd[0].events = POLLIN;
			if (poll(rfd, 1, -1) == -1) {
				fprintf(stderr, "Error polling: %s\n", strerror(errno));
				exit(1);
			}
		}
	} else {
		fprintf(stdout, "XCUBE CLI, Copyright (c) 2013-2015, "
			"Dalian Futures Information Technology Co., Ltd.\n");
		fprintf(stdout, "Type 'help' or '?' for help.\n");
		init_readline();
		stifle_history(100);
		if (pthread_create(&thread, NULL, recv_thread, NULL) != 0) {
			fprintf(stderr, "Error initializing receiver thread\n");
			exit(1);
		}
		while (loop) {
			char *line;

			line = readline(prompt);
			if (rl_inited == 0)
				rl_inited = 1;
			if (line == NULL)
				continue;
			LTRIM(line);
			RTRIM(line);
			if (*line) {
				add_history(line);
				if (tcpsock == -1)
					execute_line(line);
				else {
					net_try_write(tcpsock, line, strlen(line), 100, NET_NONBLOCK);
					net_try_write(tcpsock, "\r\n", 2, 100, NET_NONBLOCK);
					if (!strncasecmp(line, "quit", 4))
						com_quit(NULL);
				}
			}
			FREE(line);
		}
	}
	return 0;
}

static int com_help(char *arg) {
	int i;
	NOT_USED(arg);

	for (i = 0; commands[i].name; ++i)
		fprintf(stdout, "%30.30s  %s\n", commands[i].name, commands[i].doc);
	return 0;
}

static int com_quit(char *arg) {
	NOT_USED(arg);

	loop = 0;
	return 0;
}

