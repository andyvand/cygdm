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
#define DM_DRIVER_EMAIL "lvm-devel@lists.sistina.com"
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

	int mode;

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

	/*
	 * Indicates the rw permissions for the new logical
	 * device.  This should be a combination of FMODE_READ
	 * and FMODE_WRITE.
	 */
	int mode;

	/* a list of devices used by this table */
	struct list_head devices;

	/*
	 * A waitqueue for processes waiting for something
	 * interesting to happen to this table.
	 */
	wait_queue_head_t eventq;
};

/*
 * The actual device struct
 */
struct mapped_device {
	struct rw_semaphore lock;
	unsigned long flags;

	kdev_t dev;
	char *name;
	char *uuid;

	int use_count;

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

/*
 * dm-hash manages the lookup of devices by dev/name/uuid.
 */
int dm_hash_init(void);
void dm_hash_exit(void);

int dm_hash_insert(struct mapped_device *md);
void dm_hash_remove(struct mapped_device *md);
int dm_hash_rename(const char *old, const char *new);

/*
 * There are three ways to lookup a device: by kdev_t, by name
 * and by uuid.  A code path (eg an ioctl) should only ever get
 * one device at any time.
 */
struct mapped_device *dm_get_r(kdev_t dev);
struct mapped_device *dm_get_w(kdev_t dev);

struct mapped_device *dm_get_name_r(const char *name);
struct mapped_device *dm_get_name_w(const char *name);

struct mapped_device *dm_get_uuid_r(const char *uuid);
struct mapped_device *dm_get_uuid_w(const char *uuid);

static inline void dm_put_r(struct mapped_device *md)
{
	up_read(&md->lock);
}

static inline void dm_put_w(struct mapped_device *md)
{
	up_write(&md->lock);
}

/*
 * Call with no lock.
 */
int dm_create(const char *name, const char *uuid, int minor, int ro,
	      struct dm_table *table);
int dm_set_name(const char *name, const char *newname);
void dm_destroy_all(void);

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
int dm_suspend(kdev_t dev);
int dm_resume(kdev_t dev);

/* dm-table.c */
int dm_table_create(struct dm_table **result, int mode);
void dm_table_destroy(struct dm_table *t);

int dm_table_add_target(struct dm_table *t, offset_t highs,
			struct target_type *type, void *private);
int dm_table_complete(struct dm_table *t);

/*
 * Event handling
 */
void dm_table_event(struct dm_table *t);

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

static inline int array_too_big(unsigned long fixed, unsigned long obj,
				unsigned long num)
{
	return (num > (ULONG_MAX - fixed) / obj);
}

static inline char *dm_strdup(const char *str)
{
	char *r = kmalloc(strlen(str) + 1, GFP_KERNEL);
	if (r)
		strcpy(r, str);
	return r;
}

/*
 * Flags in struct mapped_device
 */

#define DMF_VALID	0
#define DMF_SUSPENDED	1
#define DMF_RO		2

static inline int dm_flag(struct mapped_device *md, int flag)
{
	return (md->flags & (1 << flag));
}

static inline void dm_set_flag(struct mapped_device *md, int flag)
{
	md->flags |= (1 << flag);
}

static inline void dm_clear_flag(struct mapped_device *md, int flag)
{
	md->flags &= ~(1 << flag);
}

/*
 * Targets
 */
int dm_linear_init(void);
void dm_linear_exit(void);

int dm_stripe_init(void);
void dm_stripe_exit(void);

int dm_snapshot_init(void);
void dm_snapshot_exit(void);

/* Future */
/* int dm_mirror_init(void); */
/* void dm_mirror_exit(void); */

/*
 * Init functions for the user interface to device-mapper.  At
 * the moment an ioctl interface on a special char device is
 * used.  A filesystem based interface would be a nicer way to
 * go.
 */
int __init dm_interface_init(void);
void dm_interface_exit(void);

#endif
