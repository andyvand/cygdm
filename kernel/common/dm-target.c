/*
 * Copyright (C) 2001 Sistina Software (UK) Limited
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include <linux/kmod.h>

struct tt_internal {
	struct target_type tt;

	struct list_head list;
	long use;
};

static LIST_HEAD(_targets);
static rwlock_t _lock = RW_LOCK_UNLOCKED;

#define DM_MOD_NAME_SIZE 32

/*
 * Destructively splits up the argument list to pass to ctr.
 */
int split_args(int max, int *argc, char **argv, char *input)
{
	char *start, *end = input, *out;
	*argc = 0;

	while (1) {
		start = end;

		/* Skip whitespace */
		while(*start && isspace(*start))
			start++;

		if (!*start)
			break; /* success, we hit the end */

		/* 'out' is used to remove any back-quotes */
		end = out = start;
		while(*end) {
			/* Everything apart from '\0' can be quoted */
			if (*end == '\\' && *(end + 1)) {
				*out++ = *(end + 1);
				end += 2;
				continue;
			}

			if (isspace(*end))
				break; /* end of token */

			*out++ = *end++;
		}

		/* have we already filled the array ? */
		if ((*argc + 1) > max)
			return -EINVAL;

		/* terminate the string and put it in the array */
		*out = '\0';
		end++;
		argv[*argc] = start;
		(*argc)++;
	}

	return 0;
}

static inline struct tt_internal *__find_target_type(const char *name)
{
	struct list_head *tih;
	struct tt_internal *ti;

	list_for_each(tih, &_targets) {
		ti = list_entry(tih, struct tt_internal, list);

		if (!strcmp(name, ti->tt.name))
			return ti;
	}

	return NULL;
}

static struct tt_internal *get_target_type(const char *name)
{
	struct tt_internal *ti;

	read_lock(&_lock);
	ti = __find_target_type(name);

	if (ti) {
		if (ti->use == 0 && ti->tt.module)
			__MOD_INC_USE_COUNT(ti->tt.module);
		ti->use++;
	}
	read_unlock(&_lock);

	return ti;
}

static void load_module(const char *name)
{
	char module_name[DM_MOD_NAME_SIZE] = "dm-";

	/* Length check for strcat() below */
	if (strlen(name) > (DM_MOD_NAME_SIZE - 4))
		return;

	strcat(module_name, name);
	request_module(module_name);

	return;
}

struct target_type *dm_get_target_type(const char *name)
{
	struct tt_internal *ti = get_target_type(name);

	if (!ti) {
		load_module(name);
		ti = get_target_type(name);
	}

	return ti ? &ti->tt : NULL;
}

void dm_put_target_type(struct target_type *t)
{
	struct tt_internal *ti = (struct tt_internal *) t;

	read_lock(&_lock);
	if (--ti->use == 0 && ti->tt.module)
		__MOD_DEC_USE_COUNT(ti->tt.module);

	if (ti->use < 0)
		BUG();
	read_unlock(&_lock);

	return;
}

static struct tt_internal *alloc_target(struct target_type *t)
{
	struct tt_internal *ti = kmalloc(sizeof(*ti), GFP_KERNEL);

	if (ti) {
		memset(ti, 0, sizeof(*ti));
		ti->tt = *t;
	}

	return ti;
}

int dm_register_target(struct target_type *t)
{
	int rv = 0;
	struct tt_internal *ti = alloc_target(t);

	if (!ti)
		return -ENOMEM;

	write_lock(&_lock);
	if (__find_target_type(t->name))
		rv = -EEXIST;
	else
		list_add(&ti->list, &_targets);

	write_unlock(&_lock);
	return rv;
}

int dm_unregister_target(struct target_type *t)
{
	struct tt_internal *ti;

	write_lock(&_lock);
	if (!(ti = __find_target_type(t->name))) {
		write_unlock(&_lock);
		return -EINVAL;
	}

	if (ti->use) {
		write_unlock(&_lock);
		return -ETXTBSY;
	}

	list_del(&ti->list);
	kfree(ti);

	write_unlock(&_lock);
	return 0;
}

/*
 * io-err: always fails an io, useful for bringing
 * up LV's that have holes in them.
 */
static int io_err_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **args, void **context)
{
	*context = NULL;
	return 0;
}

static void io_err_dtr(struct dm_table *t, void *c)
{
	/* empty */
	return;
}

static int io_err_map(struct buffer_head *bh, int rw, void *context)
{
	buffer_IO_error(bh);
	return 0;
}

static struct target_type error_target = {
	name:	"error",
	ctr:	io_err_ctr,
	dtr:	io_err_dtr,
	map:	io_err_map,
};

int dm_target_init(void)
{
	return dm_register_target(&error_target);
}

void dm_target_exit(void)
{
	if (dm_unregister_target(&error_target))
		WARN("unregister of error target failed.");
}

EXPORT_SYMBOL(dm_register_target);
EXPORT_SYMBOL(dm_unregister_target);
