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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "mem.h"
#include "dlist.h"
#include "table.h"
#include "dstr.h"
#include "logger.h"
#include "net.h"
#include "db.h"
#include "utilities.h"
#include "commons.h"

/* FIXME */
struct crss {
	client	c;
	dstr	rid, match, start, stop;
	int	cancel;
};

/* FIXME */
extern table_t cache;
extern table_t subscribers;
extern int persistence;
extern db_t *db;
extern db_readoptions_t *db_ro;
extern table_t idxfmts;
extern const char *password;
extern const char *dpip;
extern int dpport;

/* FIXME */
static table_t rids = NULL;

/* FIXME */
int cmpkvd(const void *x, const void *y) {
	return strcmp(((struct kvd *)x)->key, ((struct kvd *)y)->key);
}

/* FIXME */
void kvfree(void *value) {
	struct kvd *kvd = (struct kvd *)value;

	dstr_free(kvd->key);
	dstr_free(kvd->u.value);
	FREE(kvd);
}

/* FIXME */
void kdfree(void *value) {
	struct kvd *kvd = (struct kvd *)value;

	dstr_free(kvd->key);
	dlist_free(&kvd->u.dlist);
	FREE(kvd);
}

/* FIXME */
void s_command(client c) {
	dstr pkey, skey;
	int i;
	dlist_t dlist;
	struct kvd *kvd;

	if (dstr_length(c->argv[0]) == 1) {
		add_reply_error(c, "index can't be empty\r\n");
		return;
	}
	pkey = dstr_new(c->argv[0] + 1);
	skey = dstr_new(pkey);
	if (c->argc > 1)
		for (i = 1; i < c->argc; ++i) {
			skey = dstr_cat(skey, ",");
			skey = dstr_cat(skey, c->argv[i]);
		}
	table_lock(cache);
	if ((dlist = table_get_value(cache, pkey))) {
		dlist_iter_t iter = dlist_iter_new(dlist, DLIST_START_HEAD);
		dlist_node_t node;

		/* still has room to improve */
		while ((node = dlist_next(iter))) {
			kvd = (struct kvd *)dlist_node_value(node);
			if (dstr_length(kvd->key) >= dstr_length(skey) &&
				!memcmp(kvd->key, skey, dstr_length(skey))) {
				dstr *fields = NULL;
				int nfield = 0;
				dstr res, contracts = NULL;

				fields = dstr_split_len(kvd->key, dstr_length(kvd->key), ",", 1, &nfield);
				res = dstr_new(fields[0]);
				if (nfield > 1) {
					contracts = dstr_new(fields[1]);
					for (i = 2; i < nfield; ++i) {
						contracts = dstr_cat(contracts, ",");
						contracts = dstr_cat(contracts, fields[i]);
					}
				}
				dstr_free_tokens(fields, nfield);
				fields = NULL, nfield = 0;
				fields = dstr_split_len(kvd->u.value, dstr_length(kvd->u.value),
					",", 1, &nfield);
				res = dstr_cat(res, ",");
				res = dstr_cat(res, fields[0]);
				if (contracts) {
					res = dstr_cat(res, ",");
					res = dstr_cat(res, contracts);
				}
				for (i = 1; i < nfield; ++i) {
					res = dstr_cat(res, ",");
					res = dstr_cat(res, fields[i]);
				}
				res = dstr_cat(res, "\r\n");
				pthread_spin_lock(&c->lock);
				if (!(c->flags & CLIENT_CLOSE_ASAP)) {
					if (net_try_write(c->fd, res, dstr_length(res), 10, NET_NONBLOCK) == -1) {
						xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
							c, strerror(errno));
						if (++c->eagcount >= 10)
							client_free_async(c);
					} else if (c->eagcount)
						c->eagcount = 0;
				}
				pthread_spin_unlock(&c->lock);
				dstr_free(contracts);
				dstr_free(res);
				dstr_free_tokens(fields, nfield);
			}
		}
		dlist_iter_free(&iter);
	}
	table_unlock(cache);
	table_rwlock_wrlock(subscribers);
	if ((dlist = table_get_value(subscribers, pkey)) == NULL) {
		if (NEW(kvd)) {
			kvd->key     = skey;
			kvd->u.dlist = dlist_new(NULL, NULL);
			dlist_insert_tail(kvd->u.dlist, c);
			dlist = dlist_new(cmpkvd, kdfree);
			dlist_insert_sort(dlist, kvd);
			table_insert(subscribers, pkey, dlist);
		} else {
			add_reply_error(c, "error allocating memory for kvd\r\n");
			dstr_free(skey);
			dstr_free(pkey);
		}
	} else {
		if (NEW(kvd)) {
			dlist_node_t node;

			kvd->key     = skey;
			kvd->u.dlist = dlist_new(NULL, NULL);
			if ((node = dlist_find(dlist, kvd)) == NULL) {
				dlist_insert_tail(kvd->u.dlist, c);
				dlist_insert_sort(dlist, kvd);
			} else {
				kdfree(kvd);
				kvd = (struct kvd *)dlist_node_value(node);
				if (dlist_find(kvd->u.dlist, c) == NULL)
					dlist_insert_tail(kvd->u.dlist, c);
			}
		} else {
			add_reply_error(c, "error allocating memory for kvd\r\n");
			dstr_free(skey);
		}
		dstr_free(pkey);
	}
	table_rwlock_unlock(subscribers);
}

/* FIXME */
void u_command(client c) {
	dstr pkey, skey;
	dlist_t dlist;

	if (dstr_length(c->argv[0]) == 1) {
		add_reply_error(c, "index can't be empty\r\n");
		return;
	}
	pkey = dstr_new(c->argv[0] + 1);
	skey = dstr_new(pkey);
	if (c->argc > 1) {
		int i;

		for (i = 1; i < c->argc; ++i) {
			skey = dstr_cat(skey, ",");
			skey = dstr_cat(skey, c->argv[i]);
		}
	}
	table_rwlock_wrlock(subscribers);
	if ((dlist = table_get_value(subscribers, pkey))) {
		struct kvd *kvd;

		if (NEW(kvd)) {
			dlist_node_t node, node2;

			kvd->key = skey;
			if ((node = dlist_find(dlist, kvd))) {
				FREE(kvd);
				kvd = (struct kvd *)dlist_node_value(node);
				if ((node2 = dlist_find(kvd->u.dlist, c)))
					dlist_remove(kvd->u.dlist, node2);
				if (dlist_length(kvd->u.dlist) == 0) {
					dlist_remove(dlist, node);
					kdfree(kvd);
				}
				if (dlist_length(dlist) == 0) {
					table_remove(subscribers, pkey);
					dlist_free(&dlist);
				}
			} else
				FREE(kvd);
		} else
			add_reply_error(c, "error allocating memory for kvd");
	}
	table_rwlock_unlock(subscribers);
	dstr_free(skey);
	dstr_free(pkey);
	add_reply_string(c, "\r\n", 2);
}

/* FIXME */
static void kfree(const void *key) {
	dstr_free((dstr)key);
}

/* FIXME */
static void *q_thread(void *data) {
	struct crss *crss = (struct crss *)data;
	char buf[64];
	dstr rid, res = NULL;
	db_iterator_t *it;
	const char *key, *value;
	size_t klen, vlen;

	snprintf(buf, sizeof buf, "%p,", crss->c);
	rid = dstr_new(buf);
	rid = dstr_cat(rid, crss->rid);
	it = db_iterator_create(db, db_ro);
	db_iterator_seek(it, crss->start, dstr_length(crss->start));
	/* seek failed */
	if (!db_iterator_valid(it)) {
		res = dstr_new(crss->rid);
		res = dstr_cat(res, ",1\r\n\r\n");
		pthread_spin_lock(&crss->c->lock);
		if (net_try_write(crss->c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1)
			xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s", crss->c, strerror(errno));
		pthread_spin_unlock(&crss->c->lock);
		goto end;
	}
	key = db_iterator_key(it, &klen);
	while (memcmp(key, crss->stop, dstr_length(crss->stop)) <= 0) {
		if (crss->cancel)
			break;
		if (!strcmp(crss->match, "") || strstr(key, crss->match)) {
			value = db_iterator_value(it, &vlen);
			res = dstr_new(crss->rid);
			res = dstr_cat(res, ",0,");
			res = dstr_cat_len(res, key, klen);
			res = dstr_cat(res, ",");
			res = dstr_cat_len(res, value, vlen);
			res = dstr_cat(res, "\r\n");
			pthread_spin_lock(&crss->c->lock);
			if (net_try_write(crss->c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1) {
				xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s",
					crss->c, strerror(errno));
				pthread_spin_unlock(&crss->c->lock);
				goto end;
			}
			pthread_spin_unlock(&crss->c->lock);
			dstr_free(res);
		}
		db_iterator_next(it);
		if (!db_iterator_valid(it) || crss->cancel)
			break;
		key = db_iterator_key(it, &klen);
	}
	res = dstr_new(crss->rid);
	res = dstr_cat(res, ",1\r\n\r\n");
	pthread_spin_lock(&crss->c->lock);
	if (net_try_write(crss->c->fd, res, dstr_length(res), 100, NET_NONBLOCK) == -1)
		xcb_log(XCB_LOG_WARNING, "Writing to client '%p': %s", crss->c, strerror(errno));
	pthread_spin_unlock(&crss->c->lock);

end:
	db_iterator_destroy(&it);
	dstr_free(res);
	table_lock(rids);
	table_remove(rids, rid);
	table_unlock(rids);
	dstr_free(rid);
	client_decr(crss->c);
	dstr_free(crss->rid);
	dstr_free(crss->match);
	dstr_free(crss->start);
	dstr_free(crss->stop);
	FREE(crss);
	return NULL;
}

/* FIXME */
void q_command(client c) {
	struct tm tm;
	char *end;
	char buf[64];
	dstr rid;
	struct crss *crss;

	if (!persistence) {
		add_reply_error(c, "database not open\r\n");
		return;
	}
	if (dstr_length(c->argv[0]) == 1) {
		add_reply_error(c, "index can't be empty\r\n");
		return;
	}
	if ((end = strptime(c->argv[3], "%F %T", &tm)) && *end == '\0')
		c->argv[3] = dstr_cat(c->argv[3], ".000");
	else if ((end = strptime(c->argv[3], "%F %R", &tm)) && *end == '\0')
		c->argv[3] = dstr_cat(c->argv[3], ":00.000");
	else {
		add_reply_error(c, "invalid time format, "
			"please use 'YYYY-mm-dd HH:MM:SS' or 'YYYY-mm-dd HH:MM'.\r\n");
		return;
	}
	if ((end = strptime(c->argv[4], "%F %T", &tm)) && *end == '\0')
		c->argv[4] = dstr_cat(c->argv[4], ".999");
	else if ((end = strptime(c->argv[4], "%F %R", &tm)) && *end == '\0')
		c->argv[4] = dstr_cat(c->argv[4], ":59.999");
	else {
		add_reply_error(c, "invalid time format, "
			"please use 'YYYY-mm-dd HH:MM:SS' or 'YYYY-mm-dd HH:MM'.\r\n");
		return;
	}
	snprintf(buf, sizeof buf, "%p,", c);
	rid = dstr_new(buf);
	rid = dstr_cat(rid, c->argv[1]);
	if (rids == NULL)
		rids = table_new(cmpstr, hashmurmur2, kfree, NULL);
	table_lock(rids);
	if ((crss = table_get_value(rids, rid))) {
		add_reply_error_format(c, "query with rid '%s' already exists\r\n", c->argv[1]);
		dstr_free(rid);
	} else if (NEW(crss)) {
		pthread_t thread;

		crss->c      = c;
		crss->rid    = dstr_new(c->argv[1]);
		crss->match  = dstr_new(c->argv[2]);
		crss->start  = dstr_new(c->argv[0] + 1);
		crss->start  = dstr_cat(crss->start, ",");
		crss->start  = dstr_cat(crss->start, c->argv[3]);
		crss->stop   = dstr_new(c->argv[0] + 1);
		crss->stop   = dstr_cat(crss->stop, ",");
		crss->stop   = dstr_cat(crss->stop, c->argv[4]);
		crss->cancel = 0;
		if (pthread_create(&thread, NULL, q_thread, crss) != 0) {
			add_reply_error(c, strerror(errno));
			add_reply_string(c, "\r\n", 2);
			dstr_free(crss->rid);
			dstr_free(crss->match);
			dstr_free(crss->start);
			dstr_free(crss->stop);
			FREE(crss);
			dstr_free(rid);
		} else {
			client_incr(crss->c);
			table_insert(rids, rid, crss);
		}
	} else {
		add_reply_error(c, "error allocating memory for crss\r\n");
		dstr_free(rid);
	}
	table_unlock(rids);
}

/* FIXME */
void qc_command(client c) {
	char buf[64];
	dstr rid;
	struct crss *crss;

	snprintf(buf, sizeof buf, "%p,", c);
	rid = dstr_new(buf);
	rid = dstr_cat(rid, c->argv[1]);
	if (rids == NULL)
		rids = table_new(cmpstr, hashmurmur2, kfree, NULL);
	table_lock(rids);
	if ((crss = table_get_value(rids, rid))) {
		crss->cancel = 1;
		xcb_log(XCB_LOG_DEBUG, "Query with rid '%s' got cancelled", c->argv[1]);
	}
	table_unlock(rids);
	add_reply_string(c, "\r\n", 2);
	dstr_free(rid);
}

/* FIXME */
void index_command(client c) {
	const char *fmt;

	table_lock(idxfmts);
	if ((fmt = table_get_value(idxfmts, c->argv[1])))
		add_reply_string_format(c, "%s\r\n", fmt);
	else
		add_reply_error(c, "format unavailable");
	table_unlock(idxfmts);
	add_reply_string(c, "\r\n", 2);
}

/* FIXME */
static int cmppass(const char *a, const char *b) {
	char bufa[512], bufb[512];
	int alen = strlen(a), blen = strlen(b), i, diff = 0;

	if (alen > sizeof bufa || blen > sizeof bufb)
		return 1;
	memset(bufa, '\0', sizeof bufa);
	memset(bufb, '\0', sizeof bufb);
	memcpy(bufa, a, alen);
	memcpy(bufb, b, blen);
	for (i = 0; i < sizeof bufa; ++i)
		diff |= bufa[i] ^ bufb[i];
	diff |= alen ^ blen;
	return diff;
}

/* FIXME */
void auth_command(client c) {
	if (password == NULL)
		add_reply_error(c, "no password is set");
	else if (cmppass(password, c->argv[1]) == 0) {
		c->authenticated = 1;
		add_reply_string(c, "OK\r\n", 4);
	} else {
		c->authenticated = 0;
		add_reply_error(c, "invalid password");
	}
	add_reply_string(c, "\r\n", 2);
}

