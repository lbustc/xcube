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

#include <stdio.h>
#include <string.h>
#include "mem.h"
#include "logger.h"
#include "config.h"

/* FIXME */
#define MAX_INCLUDE_LEVEL 1

/* FIXME */
struct category {
	struct category		*next;
	char			name[80];
	char			*file;
	int			lineno;
	struct variable		*first, *last;
};
struct config_include {
	struct config_include	*next;
	char			*included_file;
};
struct config {
	struct category		*first, *last, *current, *last_browse;
	int			include_level, max_include_level;
	struct config_include	*includes;
};

static struct config *config_internal_load(const char *path, struct config *cfg);

/* FIXME */
static char *skip_blanks(const char *str) {
	while (*str && (unsigned char)*str < 33)
		++str;
	return (char *)str;
}

/* FIXME */
static char *trim_blanks(char *str) {
	char *s = str;

	if (s) {
		s += strlen(s) - 1;
		while (s >= str && (unsigned char)*s < 33)
			*s-- = '\0';
	}
	return str;
}

static char *strip(char *str) {
	if ((str = skip_blanks(str)))
		trim_blanks(str);
	return str;
}

/* FIXME */
static struct variable *variable_new(const char *name, const char *value, const char *file, int lineno) {
	struct variable *var;
	size_t nlen = strlen(name) + 1, vlen = strlen(value) + 1, flen = strlen(file) + 1;

	if ((var = CALLOC(1, sizeof *var + nlen + vlen + flen))) {
		char *dst = var->staff;

		var->name   = strcpy(dst, name);
		dst += nlen;
		var->value  = strcpy(dst, value);
		dst += vlen;
		var->file   = strcpy(dst, file);
		var->lineno = lineno;
	}
	return var;
}

static inline void variable_destroy(struct variable *var) {
	FREE(var);
}

static void variable_append(struct category *cat, struct variable *var) {
	if (cat->last)
		cat->last->next = var;
	else
		cat->first = var;
	cat->last = var;
}

static void variables_destroy(struct variable *var) {
	while (var) {
		struct variable *v = var;

		var = var->next;
		variable_destroy(v);
	}
}

static struct category *category_new(const char *name, const char *file, int lineno) {
	struct category *cat;

	if (NEW0(cat) == NULL)
		return NULL;
	if ((cat->file = mem_strdup(file)) == NULL) {
		FREE(cat);
		return NULL;
	}
	/* FIXME */
	strncpy(cat->name, name, sizeof cat->name);
	cat->lineno = lineno;
	return cat;
}

static void category_destroy(struct category *cat) {
	variables_destroy(cat->first);
	FREE(cat->file);
	FREE(cat);
}

static void category_append(struct config *cfg, struct category *cat) {
	if (cfg->last)
		cfg->last->next = cat;
	else
		cfg->first = cat;
	cfg->last    = cat;
	cfg->current = cat;
}

static struct config *config_new(void) {
	struct config *cfg;

	if (NEW0(cfg))
		cfg->max_include_level = MAX_INCLUDE_LEVEL;
	return cfg;
}

/* FIXME */
static struct config_include *config_include_new(struct config *cfg, const char *included_file) {
	struct config_include *include;

	if (NEW(include) == NULL)
		return NULL;
	if ((include->included_file = mem_strdup(included_file)) == NULL) {
		FREE(include);
		return NULL;
	}
	include->next = cfg->includes;
	cfg->includes = include;
	return include;
}

static void config_includes_destroy(struct config_include *include) {
	while (include) {
		struct config_include *inc = include;

		include = include->next;
		FREE(inc->included_file);
		FREE(inc);
	}
}

static int process_text_line(char *buf, struct category **cat, struct config *cfg,
	int lineno, const char *configfile) {
	char *curr = buf, *c;

	/* a category header */
	if (curr[0] == '[') {
		if ((c = strchr(curr, ']')) == NULL) {
			xcb_log(XCB_LOG_WARNING, "no closing ']', line %d of '%s'", lineno, configfile);
			return -1;
		}
		*c = '\0';
		++curr;
		/* FIXME */
		if ((*cat = category_new(curr, cfg->include_level == 1 ? "" : configfile, lineno)) == NULL)
			return -1;
		category_append(cfg, *cat);
	/* directive #include */
	} else if (curr[0] == '#') {
		++curr;
		c = curr;
		while (*c && *c > 32)
			++c;
		if (*c) {
			*c = '\0';
			c = strip(c + 1);
			if (*c == '\0')
				c = NULL;
		} else
			c = NULL;
		if (strcasecmp(curr, "include")) {
			xcb_log(XCB_LOG_WARNING, "Unknown directive '#%s' at line %d of %s",
				curr, lineno, configfile);
			return 0;
		}
		if (c == NULL) {
			xcb_log(XCB_LOG_WARNING, "Directive '#include' needs an argument (filename)"
				"at line %d of %s", lineno, configfile);
			return 0;
		}
		curr = c;
		if (*c == '"' || *c == '<') {
			char quote_char = *c;

			if (quote_char == '<')
				quote_char = '>';
			if (*(c + strlen(c) - 1) == quote_char) {
				++curr;
				*(c + strlen(c) - 1) = '\0';
			}
		}
		/* FIXME */
		config_include_new(cfg, curr);
		if (config_internal_load(curr, cfg) == NULL)
			return -1;
	/* just a line (variable = value) */
	} else {
		struct variable *var;

		if (*cat == NULL) {
			xcb_log(XCB_LOG_WARNING, "no category context for line %d of '%s'",
				lineno, configfile);
			return -1;
		}
		if ((c = strchr(curr, '=')) == NULL) {
			xcb_log(XCB_LOG_WARNING, "no '=' (equal sign) in line %d of '%s'",
			lineno, configfile);
			return -1;
		}
		*c++ = '\0';
		/* FIXME */
		if ((var = variable_new(strip(curr), strip(c),
			cfg->include_level == 1 ? "" : configfile, lineno)) == NULL)
			return -1;
		variable_append(*cat, var);
	}
	return 0;
}

static struct config *config_internal_load(const char *path, struct config *cfg) {
	int count = 0;

	/* FIXME */
	if (cfg->max_include_level > 0 && cfg->include_level == cfg->max_include_level + 1) {
		xcb_log(XCB_LOG_WARNING, "Maximum include level (%d) exceeded", cfg->max_include_level);
		return NULL;
	}
	++cfg->include_level;
	do {
		FILE *fp;
		int lineno = 0;
		char buf[8192], *new_buf;
		struct category *cat = NULL;

		/* FIXME */
		if ((fp = fopen(path, "r")) == NULL) {
			xcb_log(XCB_LOG_WARNING, "Error opening file '%s'", path);
			continue;
		}
		++count;
		while (!feof(fp)) {
			++lineno;
			if (fgets(buf, sizeof buf, fp)) {
				/* FIXME: skip lines that are too long */
				if (strlen(buf) == sizeof buf - 1 && buf[sizeof buf - 1] != '\n') {
					xcb_log(XCB_LOG_WARNING, "Line %d too long, skipping.", lineno);
					while (fgets(buf, sizeof buf, fp))
						if (strlen(buf) != sizeof buf - 1 ||
							buf[sizeof buf - 1] == '\n')
							break;
					continue;
				}
				/* blank line */
				if (strlen(buf) == strspn(buf, " \t\n\r"))
					continue;
				new_buf = strip(buf);
				/* FIXME: comment line */
				if (new_buf[0] == ';')
					continue;
				/* FIXME: hack? */
				if (process_text_line(new_buf, &cat, cfg, lineno, path) < 0) {
					count = 0;
					break;
				}
			}
		}
		fclose(fp);
	} while (0);
	if (count == 0)
		return NULL;
	--cfg->include_level;
	return cfg;
}

struct config *config_load(const char *path) {
	struct config *cfg, *result;

	if ((cfg = config_new()) == NULL)
		return NULL;
	if ((result = config_internal_load(path, cfg)) == NULL)
		config_destroy(cfg);
	return result;
}

void config_destroy(struct config *cfg) {
	struct category *cat;

	if (cfg == NULL)
		return;
	config_includes_destroy(cfg->includes);
	cat = cfg->first;
	while (cat) {
		struct category *c = cat;

		cat = cat->next;
		category_destroy(c);
	}
	FREE(cfg);
}

char *category_browse(struct config *cfg, const char *prev) {
	struct category *cat;

	if (cfg == NULL)
		return NULL;
	if (prev == NULL)
		cat = cfg->first;
	else if (cfg->last_browse && cfg->last_browse->name == prev)
		cat = cfg->last_browse->next;
	else {
		for (cat = cfg->first; cat; cat = cat->next)
			if (cat->name == prev) {
				cat = cat->next;
				break;
			}
		if (cat == NULL)
			for (cat = cfg->first; cat; cat = cat->next)
				if (!strcasecmp(cat->name, prev)) {
					cat = cat->next;
					break;
				}
	}
	cfg->last_browse = cat;
	return cat ? cat->name : NULL;
}

struct variable *variable_browse(struct config *cfg, const char *category) {
	struct category *cat;

	if (cfg == NULL || category == NULL)
		return NULL;
	if (cfg->last_browse && cfg->last_browse->name == category)
		cat = cfg->last_browse;
	else
		cat = category_get(cfg, category);
	return cat ? cat->first : NULL;
}

const char *variable_retrieve(struct config *cfg, const char *category, const char *variable) {
	struct variable *var;

	if (cfg == NULL)
		return NULL;
	if (category) {
		for (var = variable_browse(cfg, category); var; var = var->next)
			if (!strcasecmp(var->name, variable))
				return var->value;
	} else {
		struct category *cat;

		for (cat = cfg->first; cat; cat = cat->next)
			for (var = cat->first; var; var = var->next)
				if (!strcasecmp(var->name, variable))
					return var->value;
	}
	return NULL;
}

struct category *category_get(struct config *cfg, const char *category) {
	struct category *cat;

	if (cfg == NULL)
		return NULL;
	for (cat = cfg->first; cat; cat = cat->next)
		if (cat->name == category)
			return cat;
	for (cat = cfg->first; cat; cat = cat->next)
		if (!strcasecmp(cat->name, category))
			return cat;
	return NULL;
}

int variable_update(struct category *cat, const char *variable, const char *value) {
	struct variable *curr, *prev = NULL, *var;

	if (cat == NULL)
		return -1;
	for (curr = cat->first; curr; prev = curr, curr = curr->next) {
		if (strcasecmp(curr->name, variable))
			continue;
		if ((var = variable_new(variable, value, curr->file, curr->lineno)) == NULL)
			return -1;
		var->next = curr->next;
		if (prev == NULL)
			cat->first = var;
		else
			prev->next = var;
		if (cat->last == curr)
			cat->last = var;
		variable_destroy(curr);
		return 0;
	}
	return -1;
}

