/*
 * dm.h
 *
 * Internal header file for device mapper
 *
 * Copyright (C) 2001 Sistina Software
 *
 * This file is released under the LGPL.
 */

#ifndef DM_INTERNAL_H
#define DM_INTERNAL_H

#include <linux/version.h>
#include <linux/major.h>
#include <linux/iobuf.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/compatmac.h>
#include <linux/cache.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/ctype.h>
#include <linux/device-mapper.h>
#include <linux/list.h>

#define MAX_DEPTH 16
#define NODE_SIZE L1_CACHE_BYTES
#define KEYS_PER_NODE (NODE_SIZE / sizeof(offset_t))
#define CHILDREN_PER_NODE (KEYS_PER_NODE + 1)

/*
 * List of devices that a metadevice uses and should open/close.
 */
struct dm_dev {
	atomic_t count;
	struct list_head list;

	kdev_t dev;
	struct block_device *bd;
};

/*
 * I/O that had to be deferred while we were suspended
 */
struct deferred_io {
	int rw;
	struct buffer_head *bh;
	struct deferred_io *next;
};

/*
 * Btree leaf - this does the actual mapping
 */
struct target {
	struct target_type *type;
	void *private;
};

/*
 * The btree
 */
struct dm_table {
	/* btree table */
	int depth;
	int counts[MAX_DEPTH];	/* in nodes */
	offset_t *index[MAX_DEPTH];

	int num_targets;
	int num_allocated;
	offset_t *highs;
	struct target *targets;

	/* a list of devices used by this table */
	struct list_head devices;
};

/*
 * The actual device struct
 */
struct mapped_device {
	kdev_t dev;
	char name[DM_NAME_LEN];

	int use_count;
	int suspended;

	/* a list of io's that arrived while we were suspended */
	atomic_t pending;
	wait_queue_head_t wait;
	struct deferred_io *deferred;

	struct dm_table *map;

	/* used by dm-fs.c */
	devfs_handle_t devfs_entry;
};

extern struct block_device_operations dm_blk_dops;

/* dm-target.c */
int dm_target_init(void);
struct target_type *dm_get_target_type(const char *name);
void dm_put_target_type(struct target_type *t);

/* dm.c */
struct mapped_device *dm_find_by_minor(int minor);
struct mapped_device *dm_get(const char *name);
struct mapped_device *dm_create(const char *name, int minor, struct dm_table *);
int dm_destroy(struct mapped_device *md);
int dm_swap_table(struct mapped_device *md, struct dm_table *t);
int dm_suspend(struct mapped_device *md);
int dm_resume(struct mapped_device *md);

/* dm-table.c */
struct dm_table *dm_table_create(void);
void dm_table_destroy(struct dm_table *t);

int dm_table_add_target(struct dm_table *t, offset_t high,
			struct target_type *type, void *private);
int dm_table_complete(struct dm_table *t);

#define WARN(f, x...) printk(KERN_WARNING "device-mapper: " f "\n" , ## x)

/*
 * Calculate the index of the child node of the n'th node k'th key.
 */
static inline int get_child(int n, int k)
{
	return (n * CHILDREN_PER_NODE) + k;
}

/*
 * Return the n'th node of level l from table t.
 */
static inline offset_t *get_node(struct dm_table *t, int l, int n)
{
	return t->index[l] + (n * KEYS_PER_NODE);
}

int dm_interface_init(void) __init;
void dm_interface_exit(void) __exit;

#endif
