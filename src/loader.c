/*
 * Copyright (C) 1999 - 2006, Digium, Inc.
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

#include "fmacros.h"
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "mem.h"
#include "logger.h"
#include "module.h"

/* FIXME */
static struct module_list {
	struct module		*first;
	struct module		*last;
	pthread_mutex_t		lock;
} module_list = {
	.first = NULL,
	.last  = NULL,
	.lock  = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP,
};
static struct module *module_being_loaded;
static struct application_list {
	struct application	*first;
	struct application	*last;
	pthread_rwlock_t	lock;
} application_list = {
	.first = NULL,
	.last  = NULL,
	.lock  = PTHREAD_RWLOCK_INITIALIZER,
};

/* FIXME */
static struct module *find_module(const char *mod_name) {
	struct module *mod = NULL;

	for (mod = module_list.first; mod; mod = mod->link)
		if (!strcasecmp(mod->name, mod_name))
			break;
	return mod;
}

static struct module *load_dynamic_module(const char *dir, const char *mod_name) {
	char path[PATH_MAX];
	void *lib;

	if ((module_being_loaded = CALLOC(1, sizeof *module_being_loaded + strlen(mod_name) + 1)) == NULL)
		return NULL;
	strcpy(module_being_loaded->name, mod_name);
	snprintf(path, sizeof path, "%s/%s", dir, mod_name);
	if ((lib = dlopen(path, RTLD_LAZY | RTLD_LOCAL)) == NULL) {
		xcb_log(XCB_LOG_WARNING, "Error loading module '%s': %s", mod_name, dlerror());
		FREE(module_being_loaded);
		return NULL;
	}
	/* FIXME */
	if (module_being_loaded != module_list.last) {
		xcb_log(XCB_LOG_WARNING, "Module '%s' did not register itself during load", mod_name);
		while (dlclose(lib) != 0);
		return NULL;
	}
	module_list.last->lib = lib;
	module_being_loaded = NULL;
	return module_list.last;
}

static int start_module(struct module *mod) {
	int res;

	if (mod->flags.running)
		return MODULE_LOAD_SUCCESS;
	if (mod->info->load == NULL)
		return MODULE_LOAD_FAILURE;
	res = mod->info->load();
	switch (res) {
	case MODULE_LOAD_SUCCESS:
		mod->flags.running = 1;
		break;
	case MODULE_LOAD_DECLINE:
		mod->flags.declined = 1;
		break;
	case MODULE_LOAD_FAILURE:
		break;
	}
	return res;
}

static void unload_dynamic_module(struct module *mod) {
	void *lib = mod->lib;

	if (lib)
		while (dlclose(lib) != 0);
}

/* FIXME */
static struct application *find_application(const char *app_name) {
	struct application *app = NULL;

	for (app = application_list.first; app; app = app->link)
		if (!strcasecmp(app->name, app_name))
			break;
	return app;
}

int module_load(const char *dir, const char *mod_name) {
	struct module *mod;
	int res = MODULE_LOAD_SUCCESS;

	pthread_mutex_lock(&module_list.lock);
	if ((mod = find_module(mod_name))) {
		if (mod->flags.running) {
			pthread_mutex_unlock(&module_list.lock);
			xcb_log(XCB_LOG_WARNING, "Module '%s' already exists", mod_name);
			return MODULE_LOAD_DECLINE;
		}
	} else
		if ((mod = load_dynamic_module(dir, mod_name)) == NULL) {
			pthread_mutex_unlock(&module_list.lock);
			xcb_log(XCB_LOG_WARNING, "Module '%s' could not be loaded", mod_name);
			return MODULE_LOAD_FAILURE;
		}
	mod->flags.declined = 0;
	res = start_module(mod);
	pthread_mutex_unlock(&module_list.lock);
	return res;
}

int module_unload(const char *mod_name) {
	struct module *mod;
	int res = -1, error = 0;

	pthread_mutex_lock(&module_list.lock);
	if ((mod = find_module(mod_name)) == NULL) {
		pthread_mutex_unlock(&module_list.lock);
		xcb_log(XCB_LOG_WARNING, "Unload failed, '%s' could not be found", mod_name);
		return -1;
	}
	/* FIXME */
	if ((res = mod->info->unload())) {
		xcb_log(XCB_LOG_WARNING, "Firm unload failed for '%s'", mod_name);
		error = 1;
	}
	if (!error)
		mod->flags.running = mod->flags.declined = 0;
	pthread_mutex_unlock(&module_list.lock);
	if (!error)
		unload_dynamic_module(mod);
	return res;
}

int module_reload(const char *mod_name) {
	struct module_list *head;
	struct module *curr;
	int res = MODULE_RELOAD_NOT_FOUND;

	pthread_mutex_lock(&module_list.lock);
	/* FIXME */
	head = &module_list;
	for (curr = head->first; curr; curr = curr->link) {
		const struct module_info *info = curr->info;

		if (strcasecmp(curr->name, mod_name))
			continue;
		if (!curr->flags.running || curr->flags.declined) {
			if (res == MODULE_RELOAD_NOT_FOUND)
				res = MODULE_RELOAD_UNINITIALIZED;
			break;
		}
		/* can't be reloaded */
		if (info->reload == NULL) {
			if (res == MODULE_RELOAD_NOT_FOUND)
				res = MODULE_RELOAD_NOT_IMPLEMENTED;
			break;
		}
		xcb_log(XCB_LOG_NOTICE, "Reloading module '%s' (%s)", curr->name, info->desc);
		if (info->reload() == MODULE_LOAD_SUCCESS)
			res = MODULE_RELOAD_SUCCESS;
		break;
	}
	pthread_mutex_unlock(&module_list.lock);
	return res;
}

void module_register(const struct module_info *info) {
	struct module *mod;

	mod = module_being_loaded;
	mod->info = info;
	/* pthread_mutex_lock(&module_list.lock); */
	/* FIXME */
	if (module_list.first == NULL)
		module_list.last = module_list.first = mod;
	else {
		module_list.last->link = mod;
		module_list.last = mod;
	}
	/* pthread_mutex_unlock(&module_list.lock); */
	*((struct module **)&info->self) = mod;
}

void module_unregister(const struct module_info *info) {
	struct module_list *head;
	struct module *mod, *curr, *next, *prev = NULL;

	pthread_mutex_lock(&module_list.lock);
	/* FIXME */
	head = &module_list;
	for (mod = head->first, curr = mod, next = mod ? mod->link : NULL;
		mod;
		prev = curr, mod = next, curr = mod, next = mod ? mod->link : NULL)
		if (mod->info == info) {
			curr->link = NULL;
			curr = prev;
			if (prev)
				prev->link = next;
			else
				head->first = next;
			if (next == NULL)
				head->last = prev;
			break;
		}
	pthread_mutex_unlock(&module_list.lock);
	if (mod)
		FREE(mod);
}

int register_application(const char *app_name, int execute(void *data, void *data2),
	const char *description, const char *format, void *mod) {
	struct application *app;

	pthread_rwlock_wrlock(&application_list.lock);
	if ((app = find_application(app_name))) {
		pthread_rwlock_unlock(&application_list.lock);
		return -1;
	}
	if ((app = CALLOC(1, sizeof *app + strlen(app_name) + 1)) == NULL) {
		pthread_rwlock_unlock(&application_list.lock);
		return -1;
	}
	app->execute = execute;
	app->desc    = description;
	app->fmt     = format;
	app->mod     = mod;
	strcpy(app->name, app_name);
	/* FIXME */
	if (application_list.first == NULL)
		application_list.last = application_list.first = app;
	else {
		application_list.last->link = app;
		application_list.last = app;
	}
	pthread_rwlock_unlock(&application_list.lock);
	return 0;
}

int unregister_application(const char *app_name) {
	struct application_list *head;
	struct application *app, *curr, *next, *prev = NULL;

	pthread_rwlock_wrlock(&application_list.lock);
	/* FIXME */
	head = &application_list;
	for (app = head->first, curr = app, next = app ? app->link : NULL;
		app;
		prev = curr, app = next, curr = app, next = app ? app->link : NULL)
		if (!strcasecmp(app->name, app_name)) {
			curr->link = NULL;
			curr = prev;
			if (prev)
				prev->link = next;
			else
				head->first = next;
			if (next == NULL)
				head->last = prev;
			break;
		}
	pthread_rwlock_unlock(&application_list.lock);
	return app ? (FREE(app), 0) : -1;
}

/* FIXME */
int (*get_application(const char *app_name))(void *data, void *data2) {
	struct application *app;

	pthread_rwlock_rdlock(&application_list.lock);
	for (app = application_list.first; app; app = app->link)
		if (!strcasecmp(app->name, app_name))
			break;
	pthread_rwlock_unlock(&application_list.lock);
	return app ? app->execute : NULL;
}

/* FIXME */
const char *get_application_name(int execute(void *data, void *data2)) {
	struct application *app;

	pthread_rwlock_rdlock(&application_list.lock);
	for (app = application_list.first; app; app = app->link)
		if (app->execute == execute)
			break;
	pthread_rwlock_unlock(&application_list.lock);
	return app ? app->name : NULL;
}

/* FIXME */
struct module *get_application_module(int execute(void *data, void *data2)) {
	struct application *app;

	pthread_rwlock_rdlock(&application_list.lock);
	for (app = application_list.first; app; app = app->link)
		if (app->execute == execute)
			break;
	pthread_rwlock_unlock(&application_list.lock);
	return app ? app->mod : NULL;
}

/* FIXME */
const char *get_application_format(int execute(void *data, void *data2)) {
	struct application *app;

	pthread_rwlock_rdlock(&application_list.lock);
	for (app = application_list.first; app; app = app->link)
		if (app->execute == execute)
			break;
	pthread_rwlock_unlock(&application_list.lock);
	return app ? app->fmt : NULL;
}

/* FIXME */
struct module *get_module_list_head(void) {
	return module_list.first;
}

/* FIXME */
struct application *get_application_list_head(void) {
	return application_list.first;
}

