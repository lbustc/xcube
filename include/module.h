/*
 * Copyright (C) 1999 - 2008, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 * Kevin P. Fleming <kpfleming@digium.com>
 * Luigi Rizzo <rizzo@icir.org>
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

#ifndef MODULE_INCLUDED
#define MODULE_INCLUDED

/* FIXME */
#define MODULE_LOAD_SUCCESS           0
#define MODULE_LOAD_DECLINE           1
#define MODULE_LOAD_FAILURE          -1
#define MODULE_RELOAD_SUCCESS         0
#define MODULE_RELOAD_NOT_FOUND       1
#define MODULE_RELOAD_UNINITIALIZED   2
#define MODULE_RELOAD_NOT_IMPLEMENTED 3
#define MODULE_RELOAD_ERROR          -1

/* FIXME: exported types */
struct module {
	struct module			*link;
	const struct module_info	*info;
	void				*lib;
	struct {
		unsigned	declined:1;
		unsigned	running:1;
	}				flags;
	char				name[0];
};
struct application {
	struct application		*link;
	int				(*execute)(void *data, void *data2);
	const char			*desc;
	const char			*fmt;
	struct module			*mod;
	char				name[0];
};
struct module_info {
	struct module			*self;
	int				(*load)(void);
	int				(*unload)(void);
	int				(*reload)(void);
	const char			*desc;
};

static const __attribute__((unused)) struct module_info *mod_info;

/* FIXME: exported functions */
extern int                 module_load(const char *dir, const char *mod_name);
extern int                 module_unload(const char *mod_name);
extern int                 module_reload(const char *mod_name);
extern void                module_register(const struct module_info *info);
extern void                module_unregister(const struct module_info *info);
extern int                 register_application(const char *app_name, int execute(void *data, void *data2),
				const char *description, const char *format, void *mod);
extern int                 unregister_application(const char *app_name);
extern int               (*get_application(const char *app_name))(void *data, void *data2);
extern const char         *get_application_name(int execute(void *data, void *data2));
extern struct module      *get_application_module(int execute(void *data, void *data2));
extern const char         *get_application_format(int execute(void *data, void *data2));
extern struct module      *get_module_list_head(void);
extern struct application *get_application_list_head(void);

/* FIXME: exported macros */
#define MODULE_INFO(load_func, unload_func, reload_func, description) \
	static struct module_info __mod_info = { \
		.load   = load_func, \
		.unload = unload_func, \
		.reload = reload_func, \
		.desc   = description, \
	}; \
	static void __attribute__((constructor)) __reg_module(void) { \
		module_register(&__mod_info); \
	} \
	static void __attribute__((destructor)) __unreg_module(void) { \
		module_unregister(&__mod_info); \
	} \
	static const struct module_info *mod_info = &__mod_info;

#endif /* MODULE_INCLUDED */

