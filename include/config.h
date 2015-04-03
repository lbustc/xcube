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

#ifndef CONFIG_INCLUDED
#define CONFIG_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

/* exported types */
struct variable {
	struct variable	*next;
	const char	*name;
	const char	*value;
	const char	*file;
	int		lineno;
	char		staff[0];
};
struct category;
struct config;

/* FIXME: exported functions */
extern struct config   *config_load(const char *path);
extern void             config_destroy(struct config *cfg);
extern char            *category_browse(struct config *cfg, const char *prev);
extern struct variable *variable_browse(struct config *cfg, const char *category);
extern const char      *variable_retrieve(struct config *cfg, const char *category, const char *variable);
extern struct category *category_get(struct config *cfg, const char *category);
extern int              variable_update(struct category *cat, const char *variable, const char *value);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_INCLUDED */

