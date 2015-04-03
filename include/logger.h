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

#ifndef LOGGER_INCLUDED
#define LOGGER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#define _A_		__FILE__, __LINE__, __PRETTY_FUNCTION__
#ifdef XCB_LOG_DEBUG
#undef XCB_LOG_DEBUG
#endif
#define __LOG_DEBUG	0
#define XCB_LOG_DEBUG	__LOG_DEBUG, _A_
#ifdef XCB_LOG_INFO
#undef XCB_LOG_INFO
#endif
#define __LOG_INFO	1
#define XCB_LOG_INFO	__LOG_INFO, _A_
#ifdef XCB_LOG_NOTICE
#undef XCB_LOG_NOTICE
#endif
#define __LOG_NOTICE	2
#define XCB_LOG_NOTICE	__LOG_NOTICE, _A_
#ifdef XCB_LOG_WARNING
#undef XCB_LOG_WARNING
#endif
#define __LOG_WARNING	3
#define XCB_LOG_WARNING	__LOG_WARNING, _A_
#ifdef XCB_LOG_ERROR
#undef XCB_LOG_ERROR
#endif
#define __LOG_ERROR	4
#define XCB_LOG_ERROR	__LOG_ERROR, _A_

/* exported functions */
extern int  init_logger(const char *path, int level);
extern void close_logger(void);
/* FIXME: file, line and function will be provided by the XCB_LOG_* macro. */
extern void xcb_log(int level, const char *file, int line, const char *function,
		const char *fmt, ...);
extern void set_logger_level(int level);
extern int  get_logger_level(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_INCLUDED */

