/*
 * device-mapper.h
 *
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

#ifndef DEVICE_MAPPER_H
#define DEVICE_MAPPER_H

#define DM_DIR "device-mapper"
#define DM_MAX_TYPE_NAME 16

#ifdef __KERNEL__

struct dm_table;
struct dm_dev;
typedef unsigned int offset_t;

typedef void (*dm_error_fn)(const char *message, void *private);

/*
 * constructor, destructor and map fn types
 */
typedef int (*dm_ctr_fn)(struct dm_table *t, offset_t b, offset_t l,
			 char *args, void **context);

typedef void (*dm_dtr_fn)(struct dm_table *t, void *c);
typedef int (*dm_map_fn)(struct buffer_head *bh, int rw, void *context);
typedef int (*dm_err_fn)(struct buffer_head *bh, int rw, void *context);
typedef char *(*dm_print_fn)(void *context);

/*
 * Contructors should call this to make sure any
 * destination devices are handled correctly
 * (ie. opened/closed).
 */
int dm_table_get_device(struct dm_table *t, const char *path,
			offset_t start, offset_t len,
			struct dm_dev **result);
void dm_table_put_device(struct dm_table *table, struct dm_dev *d);

/*
 * information about a target type
 */
struct target_type {
        const char *name;
        struct module *module;
        dm_ctr_fn ctr;
        dm_dtr_fn dtr;
        dm_map_fn map;
	dm_err_fn err;
	dm_print_fn print;
};

int dm_register_target(struct target_type *t);
int dm_unregister_target(struct target_type *t);

#endif /* __KERNEL__ */

#endif /* DEVICE_MAPPER_H */

