/*
 * Internal header file for device mapper
 *
 * Copyright (C) 2001 Sistina Software
 *
 * This file is released under the LGPL.
 */

#ifndef DM_INTERNAL_H
#define DM_INTERNAL_H


#include <linux/config.h>
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
#include <linux/init.h>

#define DM_NAME "device-mapper"	/* Name for messaging */
#define MAX_DEPTH 16
#define NODE_SIZE L1_CACHE_BYTES
#define KEYS_PER_NODE (NODE_SIZE / sizeof(offset_t))
#define CHILDREN_PER_NODE (KEYS_PER_NODE + 1)
#define MAX_ARGS 32
#define MAX_DEVICES 256

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
	int read_only;

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
void dm_target_exit(void);

/*
 * Destructively splits argument list to pass to ctr.
 */
int split_args(int max, int *argc, char **argv, char *input);


/* dm.c */
struct mapped_device *dm_get_r(int minor);
struct mapped_device *dm_get_w(int minor);
struct mapped_device *dm_get_name_r(const char *name);
struct mapped_device *dm_get_name_w(const char *name);

void dm_put_r(int minor);
void dm_put_w(int minor);

/*
 * Call with no lock.
 */
int dm_create(const char *name, int minor, struct dm_table *table);
int dm_set_name(const char *oldname, const char *newname);

/*
 * You must have the write lock before calling the remaining md
 * methods.
 */
int dm_destroy(struct mapped_device *md);
void dm_set_ro(struct mapped_device *md, int ro);

/*
 * The device must be suspended before calling this method.
 */
int dm_swap_table(struct mapped_device *md, struct dm_table *t);

/*
 * A device can still be used while suspended, but I/O is deferred.
 */
int dm_suspend(struct mapped_device *md);
int dm_resume(struct mapped_device *md);

/*
 * Event notification
 */
void dm_notify(void *target);


/* dm-table.c */
int dm_table_create(struct dm_table **result);
void dm_table_destroy(struct dm_table *t);

int dm_table_add_target(struct dm_table *t, offset_t highs,
			struct target_type *type, void *private);
int dm_table_complete(struct dm_table *t);

/* kcopyd.c */
typedef enum {COPY_CB_COMPLETE, COPY_CB_FAILED_READ, COPY_CB_FAILED_WRITE, COPY_CB_PROGRESS} copy_cb_reason_t;
int dm_blockcopy(unsigned long fromsec, unsigned long tosec, 
		 unsigned long nr_sectors,
		 kdev_t fromdev, kdev_t todev,
		 int priority, int throttle, void (*callback)(copy_cb_reason_t, void *, long), void *context);


#define DMWARN(f, x...) printk(KERN_WARNING DM_NAME ": " f "\n" , ## x)
#define DMERR(f, x...) printk(KERN_ERR DM_NAME ": " f "\n" , ## x)
#define DMINFO(f, x...) printk(KERN_INFO DM_NAME ": " f "\n" , ## x)

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

/*
 * The device-mapper can be driven through one of two interfaces;
 * ioctl or filesystem, depending which patch you have applied.
 */

int __init dm_interface_init(void);
void __exit dm_interface_exit(void);

/* Code in dm-snapshot called by dm-origin to do snapshot COW */
int dm_do_snapshot(struct dm_dev *origin, struct buffer_head *bh);

/*
 * Targets for linear and striped mappings
 */

int dm_linear_init(void);
void dm_linear_exit(void);

int dm_stripe_init(void);
void dm_stripe_exit(void);

#endif
