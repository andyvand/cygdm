/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/blk.h>
#include <linux/blkpg.h>

/* we only need this for the lv_bmap struct definition, not happy */
#include <linux/lvm.h>

#define DEFAULT_READ_AHEAD 64

static const char *_name = DM_NAME;

static int major = 0;
static int _major = 0;

struct io_hook {
	struct mapped_device *md;
	struct target *target;
	int rw;

	void (*end_io) (struct buffer_head * bh, int uptodate);
	void *context;
};

static kmem_cache_t *_io_hook_cache;

/* block device arrays */
static int _block_size[MAX_DEVICES];
static int _blksize_size[MAX_DEVICES];
static int _hardsect_size[MAX_DEVICES];

static devfs_handle_t _dev_dir;

static int request(request_queue_t * q, int rw, struct buffer_head *bh);
static int dm_user_bmap(struct inode *inode, struct lv_bmap *lvb);

static __init int local_init(void)
{
	int r;

	/* allocate a slab for the io-hooks */
	if (!_io_hook_cache &&
	    !(_io_hook_cache = kmem_cache_create("dm io hooks",
						 sizeof(struct io_hook),
						 0, 0, NULL, NULL)))
		return -ENOMEM;

	_major = major;
	r = devfs_register_blkdev(_major, _name, &dm_blk_dops);
	if (r < 0) {
		DMERR("register_blkdev failed");
		kmem_cache_destroy(_io_hook_cache);
		return r;
	}

	if (!_major)
		_major = r;

	/* set up the arrays */
	read_ahead[_major] = DEFAULT_READ_AHEAD;
	blk_size[_major] = _block_size;
	blksize_size[_major] = _blksize_size;
	hardsect_size[_major] = _hardsect_size;

	blk_queue_make_request(BLK_DEFAULT_QUEUE(_major), request);

	_dev_dir = devfs_mk_dir(0, DM_DIR, NULL);

	return 0;
}

static void local_exit(void)
{
	if (kmem_cache_destroy(_io_hook_cache))
		DMWARN("io_hooks still allocated during unregistration");
	_io_hook_cache = NULL;

	if (devfs_unregister_blkdev(_major, _name) < 0)
		DMERR("devfs_unregister_blkdev failed");

	read_ahead[_major] = 0;
	blk_size[_major] = NULL;
	blksize_size[_major] = NULL;
	hardsect_size[_major] = NULL;
	_major = 0;

	DMINFO("cleaned up");
}

/*
 * We have a lot of init/exit functions, so it seems easier to
 * store them in an array.  The disposable macro 'xx'
 * expands a prefix into a pair of function names.
 */
static struct {
	int (*init)(void);
	void (*exit)(void);

} _inits[] = {
#define xx(n) {n ## _init, n ## _exit},
	xx(local)
	xx(dm_hash)
	xx(dm_target)
	xx(dm_linear)
	xx(dm_stripe)
	xx(dm_snapshot)
/*	xx(dm_mirror) */
	xx(dm_interface)
#undef xx
};

static int __init dm_init(void)
{
	const int count = sizeof(_inits) / sizeof(*_inits);

	int r, i;

	for (i = 0; i < count; i++) {
		r = _inits[i].init();
		if (r)
			goto bad;
	}

	return 0;

      bad:
	while (i--)
		_inits[i].exit();

	return r;
}

static void __exit dm_exit(void)
{
	int i = sizeof(_inits) / sizeof(*_inits);

	dm_destroy_all();
	while (i--)
		_inits[i].exit();
}

/*
 * Block device functions
 */
static int dm_blk_open(struct inode *inode, struct file *file)
{
	struct mapped_device *md;

	md = dm_get_w(inode->i_rdev);
	if (!md)
		return -ENXIO;

	md->use_count++;
	dm_put_w(md);

	return 0;
}

static int dm_blk_close(struct inode *inode, struct file *file)
{
	struct mapped_device *md;

	md = dm_get_w(inode->i_rdev);
	if (!md)
		return -ENXIO;

	if (md->use_count < 1)
		DMWARN("incorrect reference count found in mapped_device");

	md->use_count--;
	dm_put_w(md);

	return 0;
}

/* In 512-byte units */
#define VOLUME_SIZE(minor) (_block_size[(minor)] << 1)

static int dm_blk_ioctl(struct inode *inode, struct file *file,
			uint command, unsigned long a)
{
	int minor = MINOR(inode->i_rdev);
	long size;

	if (minor >= MAX_DEVICES)
		return -ENXIO;

	switch (command) {
	case BLKROSET:
	case BLKROGET:
	case BLKRASET:
	case BLKRAGET:
	case BLKFLSBUF:
	case BLKSSZGET:
		//case BLKRRPART: /* Re-read partition tables */
		//case BLKPG:
	case BLKELVGET:
	case BLKELVSET:
	case BLKBSZGET:
	case BLKBSZSET:
		return blk_ioctl(inode->i_rdev, command, a);
		break;

	case BLKGETSIZE:
		size = VOLUME_SIZE(minor);
		if (copy_to_user((void *) a, &size, sizeof(long)))
			return -EFAULT;
		break;

	case BLKGETSIZE64:
		size = VOLUME_SIZE(minor);
		if (put_user((u64) ((u64) size) << 9, (u64 *) a))
			return -EFAULT;
		break;

	case BLKRRPART:
		return -ENOTTY;

	case LV_BMAP:
		return dm_user_bmap(inode, (struct lv_bmap *) a);

	default:
		DMWARN("unknown block ioctl 0x%x", command);
		return -ENOTTY;
	}

	return 0;
}

static inline struct io_hook *alloc_io_hook(void)
{
	return kmem_cache_alloc(_io_hook_cache, GFP_NOIO);
}

static inline void free_io_hook(struct io_hook *ih)
{
	kmem_cache_free(_io_hook_cache, ih);
}

/*
 * FIXME: We need to decide if deferred_io's need
 * their own slab, I say no for now since they are
 * only used when the device is suspended.
 */
static inline struct deferred_io *alloc_deferred(void)
{
	return kmalloc(sizeof(struct deferred_io), GFP_NOIO);
}

static inline void free_deferred(struct deferred_io *di)
{
	kfree(di);
}

/*
 * Call a target's optional error function if an I/O failed.
 */
static inline int call_err_fn(struct io_hook *ih, struct buffer_head *bh)
{
	dm_err_fn err = ih->target->type->err;

	if (err)
		return err(bh, ih->rw, ih->target->private);

	return 0;
}

/*
 * bh->b_end_io routine that decrements the pending count
 * and then calls the original bh->b_end_io fn.
 */
static void dec_pending(struct buffer_head *bh, int uptodate)
{
	struct io_hook *ih = bh->b_private;

	if (!uptodate && call_err_fn(ih, bh))
		return;

	if (atomic_dec_and_test(&ih->md->pending))
		/* nudge anyone waiting on suspend queue */
		wake_up(&ih->md->wait);

	bh->b_end_io = ih->end_io;
	bh->b_private = ih->context;
	free_io_hook(ih);

	bh->b_end_io(bh, uptodate);
}

/*
 * Add the bh to the list of deferred io.
 */
static int queue_io(struct buffer_head *bh, int rw)
{
	struct deferred_io *di = alloc_deferred();
	struct mapped_device *md;

	if (!di)
		return -ENOMEM;

	md = dm_get_w(bh->b_rdev);
	if (!md) {
		free_deferred(di);
		return -ENXIO;
	}

	if (!dm_flag(md, DMF_SUSPENDED)) {
		dm_put_w(md);
		free_deferred(di);
		return 1;
	}

	di->bh = bh;
	di->rw = rw;
	di->next = md->deferred;
	md->deferred = di;

	dm_put_w(md);

	return 0;		/* deferred successfully */
}

/*
 * Do the bh mapping for a given leaf
 */
static inline int __map_buffer(struct mapped_device *md,
			       struct buffer_head *bh, int rw, int leaf)
{
	int r;
	dm_map_fn fn;
	void *context;
	struct io_hook *ih = NULL;
	struct target *ti = md->map->targets + leaf;

	fn = ti->type->map;
	context = ti->private;

	ih = alloc_io_hook();

	if (!ih)
		return -1;

	ih->md = md;
	ih->rw = rw;
	ih->target = ti;
	ih->end_io = bh->b_end_io;
	ih->context = bh->b_private;

	r = fn(bh, rw, context);

	if (r > 0) {
		/* hook the end io request fn */
		atomic_inc(&md->pending);
		bh->b_end_io = dec_pending;
		bh->b_private = ih;

	} else if (r == 0)
		/* we don't need to hook */
		free_io_hook(ih);

	else if (r < 0) {
		free_io_hook(ih);
		return -1;
	}

	return r;
}

/*
 * Search the btree for the correct target.
 */
static inline int __find_node(struct dm_table *t, struct buffer_head *bh)
{
	int l, n = 0, k = 0;
	offset_t *node;

	for (l = 0; l < t->depth; l++) {
		n = get_child(n, k);
		node = get_node(t, l, n);

		for (k = 0; k < KEYS_PER_NODE; k++)
			if (node[k] >= bh->b_rsector)
				break;
	}

	return (KEYS_PER_NODE * n) + k;
}

static int request(request_queue_t *q, int rw, struct buffer_head *bh)
{
	struct mapped_device *md;
	int r;

	md = dm_get_r(bh->b_rdev);
	if (!md) {
		buffer_IO_error(bh);
		return 0;
	}

	/*
	 * Sanity check.
	 */
	if (bh->b_rsector & ((bh->b_size >> 9) - 1))
		DMERR("misaligned block requested logical "
		      "sector (%lu), b_size (%d)",
		      bh->b_rsector, bh->b_size);

	/*
	 * If we're suspended we have to queue
	 * this io for later.
	 */
	while (dm_flag(md, DMF_SUSPENDED)) {
		dm_put_r(md);

		if (rw == READA)
			goto bad_no_lock;

		r = queue_io(bh, rw);

		if (r < 0)
			goto bad_no_lock;

		else if (r == 0)
			return 0;	/* deferred successfully */

		/*
		 * We're in a while loop, because someone could suspend
		 * before we get to the following read lock.
		 */
		md = dm_get_r(bh->b_rdev);
		if (!md) {
			buffer_IO_error(bh);
			return 0;
		}
	}

	if ((r = __map_buffer(md, bh, rw, __find_node(md->map, bh))) < 0)
		goto bad;

	dm_put_r(md);
	return r;

      bad:
	dm_put_r(md);

      bad_no_lock:
	buffer_IO_error(bh);
	return 0;
}

static int check_dev_size(kdev_t dev, unsigned long block)
{
	/* FIXME: check this */
	int minor = MINOR(dev);
	unsigned long max_sector = (_block_size[minor] << 1) + 1;
	unsigned long sector = (block + 1) * (_blksize_size[minor] >> 9);

	return (sector > max_sector) ? 0 : 1;
}

/*
 * Creates a dummy buffer head and maps it (for lilo).
 */
static int do_bmap(kdev_t dev, unsigned long block,
		   kdev_t * r_dev, unsigned long *r_block)
{
	struct mapped_device *md;
	struct buffer_head bh;
	int r;
	struct target *t;

	md = dm_get_r(dev);
	if (!md)
		return -ENXIO;

	if (dm_flag(md, DMF_SUSPENDED)) {
		dm_put_r(md);
		return -EPERM;
	}

	if (!check_dev_size(dev, block)) {
		dm_put_r(md);
		return -EINVAL;
	}

	/* setup dummy bh */
	memset(&bh, 0, sizeof(bh));
	bh.b_blocknr = block;
	bh.b_dev = bh.b_rdev = dev;
	bh.b_size = _blksize_size[MINOR(dev)];
	bh.b_rsector = block * (bh.b_size >> 9);

	/* find target */
	t = md->map->targets + __find_node(md->map, &bh);

	/* do the mapping */
	r = t->type->map(&bh, READ, t->private);

	*r_dev = bh.b_rdev;
	*r_block = bh.b_rsector / (bh.b_size >> 9);

	dm_put_r(md);
	return r;
}

/*
 * Marshals arguments and results between user and kernel space.
 */
static int dm_user_bmap(struct inode *inode, struct lv_bmap *lvb)
{
	unsigned long block, r_block;
	kdev_t r_dev;
	int r;

	if (get_user(block, &lvb->lv_block))
		return -EFAULT;

	if ((r = do_bmap(inode->i_rdev, block, &r_dev, &r_block)))
		return r;

	if (put_user(kdev_t_to_nr(r_dev), &lvb->lv_dev) ||
	    put_user(r_block, &lvb->lv_block))
		return -EFAULT;

	return 0;
}

/*
 * See if the device with a specific minor # is free.  Inserts
 * the device into the hashes.
 */
static inline int specific_dev(int minor, struct mapped_device *md)
{
	if (minor >= MAX_DEVICES) {
		DMWARN("request for a mapped_device beyond MAX_DEVICES (%d)",
		       MAX_DEVICES);
		return -EINVAL;
	}

	md->dev = mk_kdev(_major, minor);
	if (dm_hash_insert(md))
		/* in use */
		return -EBUSY;

	return minor;
}

/*
 * Find the first free device.
 */
static int any_old_dev(struct mapped_device *md)
{
	int i;

	for (i = 0; i < MAX_DEVICES; i++)
		if (specific_dev(i, md) >= 0)
			return i;

	return -EBUSY;
}

/*
 * Allocate and initialise a blank device, then insert it into
 * the hash tables.  Caller must ensure uuid is null-terminated.
 * Device is returned with a write lock held.
 */
static struct mapped_device *alloc_dev(const char *name, const char *uuid,
				       int minor)
{
	struct mapped_device *md = kmalloc(sizeof(*md), GFP_KERNEL);

	if (!md) {
		DMWARN("unable to allocate device, out of memory.");
		return NULL;
	}

	memset(md, 0, sizeof(*md));
	init_rwsem(&md->lock);
	down_write(&md->lock);

	/*
	 * Copy in the name.
	 */
	md->name = dm_strdup(name);
	if (!md->name)
		goto bad;

	/*
	 * Copy in the uuid.
	 */
	if (uuid && *uuid) {
		md->uuid = dm_strdup(uuid);
		if (!md->uuid) {
			DMWARN("unable to allocate uuid - out of memory.");
			goto bad;
		}
	}

	/*
	 * This will have inserted the device into the hashes iff
	 * it succeeded.
	 */
	minor = (minor < 0) ? any_old_dev(md) : specific_dev(minor, md);
	if (minor < 0)
		goto bad;

	dm_clear_flag(md, DMF_SUSPENDED);
	dm_set_flag(md, DMF_VALID);
	md->use_count = 0;
	md->deferred = NULL;

	md->pending = (atomic_t) ATOMIC_INIT(0);
	init_waitqueue_head(&md->wait);
	return md;

      bad:
	if (md->name)
		kfree(md->name);

	if (md->uuid)
		kfree(md->uuid);

	kfree(md);
	return NULL;
}

static void free_dev(struct mapped_device *md)
{
	dm_hash_remove(md);
	kfree(md->name);

	if (md->uuid)
		kfree(md->uuid);

	kfree(md);
}

static int __register_device(struct mapped_device *md)
{
	md->devfs_entry =
	    devfs_register(_dev_dir, md->name, DEVFS_FL_CURRENT_OWNER,
			   MAJOR(md->dev), MINOR(md->dev),
			   S_IFBLK | S_IRUSR | S_IWUSR | S_IRGRP,
			   &dm_blk_dops, NULL);

	return 0;
}

static int __unregister_device(struct mapped_device *md)
{
	devfs_unregister(md->devfs_entry);
	return 0;
}

/*
 * The hardsect size for a mapped device is the largest hardsect size
 * from the devices it maps onto.
 */
static int __find_hardsect_size(struct list_head *devices)
{
	int result = 512, size;
	struct list_head *tmp;

	list_for_each(tmp, devices) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);
		size = get_hardsect_size(dd->dev);
		if (size > result)
			result = size;
	}

	return result;
}

/*
 * Bind a table to the device.
 */
static int __bind(struct mapped_device *md, struct dm_table *t)
{
	int minor = MINOR(md->dev);

	md->map = t;

	if (!t->num_targets) {
		_block_size[minor] = 0;
		_blksize_size[minor] = BLOCK_SIZE;
		_hardsect_size[minor] = 0;
		return 0;
	}

	/* in k */
	_block_size[minor] = (t->highs[t->num_targets - 1] + 1) >> 1;

	_blksize_size[minor] = BLOCK_SIZE;
	_hardsect_size[minor] = __find_hardsect_size(&t->devices);
	register_disk(NULL, md->dev, 1, &dm_blk_dops, _block_size[minor]);

	return 0;
}

static void __unbind(struct mapped_device *md)
{
	int minor = MINOR(md->dev);

	dm_table_destroy(md->map);
	md->map = NULL;

	_block_size[minor] = 0;
	_blksize_size[minor] = 0;
	_hardsect_size[minor] = 0;
}

static int check_name(const char *name)
{
	if (strchr(name, '/')) {
		DMWARN("invalid device name");
		return -EINVAL;
	}

	return 0;
}

/*
 * Constructor for a new device.
 */
int dm_create(const char *name, const char *uuid, int minor, int ro,
	      struct dm_table *table)
{
	int r;
	struct mapped_device *md;

	r = check_name(name);
	if (r)
		return r;

	md = alloc_dev(name, uuid, minor);
	if (!md)
		return -ENXIO;

	r = __register_device(md);
	if (r)
		goto bad;

	r = __bind(md, table);
	if (r)
		goto bad;

	dm_set_ro(md, ro);
	dm_put_w(md);
	return 0;

      bad:
	dm_put_w(md);
	free_dev(md);
	return r;
}

/*
 * Renames the device.  No lock held.
 */
int dm_set_name(const char *name, const char *new_name)
{
	int r;
	struct mapped_device *md;

	r = dm_hash_rename(name, new_name);
	if (r)
		return r;

	md = dm_get_name_w(new_name);
	r = __unregister_device(md);
	if (!r)
		r = __register_device(md);
	dm_put_w(md);
	return r;
}

/*
 * Destructor for the device.  You cannot destroy an open device.
 * Write lock must be held before calling.  md will have been
 * freed if call was successful.
 */
int dm_destroy(struct mapped_device *md)
{
	int r;

	if (md->use_count)
		return -EPERM;

	r = __unregister_device(md);
	if (r)
		return r;

	/*
	 * Signal that this md is now invalid so that nothing further
	 * can acquire its lock.
	 */
	dm_clear_flag(md, DMF_VALID);

	__unbind(md);
	free_dev(md);
	return 0;
}

/*
 * Destroy all devices - except open ones
 */
void dm_destroy_all(void)
{
	int i, some_destroyed, r;
	struct mapped_device *md;

	do {
		some_destroyed = 0;
		for (i = 0; i < MAX_DEVICES; i++) {
			md = dm_get_w(mk_kdev(_major, i));
			if (!md)
				continue;

			r = dm_destroy(md);
			if (r)
				dm_put_w(md);
			else
				some_destroyed = 1;
		}
	} while (some_destroyed);
}

/*
 * Sets or clears the read-only flag for the device.  Write lock
 * must be held.
 */
void dm_set_ro(struct mapped_device *md, int ro)
{
	if (ro)
		dm_set_flag(md, DMF_RO);
	else
		dm_clear_flag(md, DMF_RO);

	set_device_ro(md->dev, ro);
}

/*
 * Requeue the deferred buffer_heads by calling generic_make_request.
 */
static void flush_deferred_io(struct deferred_io *c)
{
	struct deferred_io *n;

	while (c) {
		n = c->next;
		generic_make_request(c->rw, c->bh);
		free_deferred(c);
		c = n;
	}
}

/*
 * Swap in a new table (destroying old one).  Write lock must be
 * held.
 */
int dm_swap_table(struct mapped_device *md, struct dm_table *table)
{
	int r;

	/* device must be suspended */
	if (!dm_flag(md, DMF_SUSPENDED))
		return -EPERM;

	__unbind(md);

	r = __bind(md, table);
	if (r)
		return r;

	return 0;
}

/*
 * We need to be able to change a mapping table under a mounted
 * filesystem.  For example we might want to move some data in
 * the background.  Before the table can be swapped with
 * dm_bind_table, dm_suspend must be called to flush any in
 * flight buffer_heads and ensure that any further io gets
 * deferred.  Write lock must be held.
 */
int dm_suspend(kdev_t dev)
{
	struct mapped_device *md;
	DECLARE_WAITQUEUE(wait, current);

	/*
	 * First we set the suspend flag so no more ios will be
	 * mapped.
	 */
	md = dm_get_w(dev);
	if (!md)
		return -ENXIO;

	if (dm_flag(md, DMF_SUSPENDED)) {
		dm_put_w(md);
		return -EINVAL;
	}

	dm_set_flag(md, DMF_SUSPENDED);
	dm_put_w(md);

	/*
	 * Then we wait for wait for the already mapped ios to
	 * complete.
	 */
	md = dm_get_r(dev);
	if (!md)
		return -ENXIO;
	if (!dm_flag(md, DMF_SUSPENDED))
		return -EINVAL;

	add_wait_queue(&md->wait, &wait);
	current->state = TASK_UNINTERRUPTIBLE;
	do {
		if (!atomic_read(&md->pending))
			break;

		schedule();

	} while (1);

	current->state = TASK_RUNNING;
	remove_wait_queue(&md->wait, &wait);
	dm_put_r(md);

	return 0;
}

int dm_resume(kdev_t dev)
{
	struct mapped_device *md;
	struct deferred_io *def;

	md = dm_get_w(dev);
	if (!md)
		return -ENXIO;

	if (!dm_flag(md, DMF_SUSPENDED) || !md->map->num_targets) {
		dm_put_w(md);
		return -EINVAL;
	}

	dm_clear_flag(md, DMF_SUSPENDED);
	def = md->deferred;
	md->deferred = NULL;
	dm_put_w(md);

	flush_deferred_io(def);
	run_task_queue(&tq_disk);

	return 0;
}

struct block_device_operations dm_blk_dops = {
	open:		dm_blk_open,
	release:	dm_blk_close,
	ioctl:		dm_blk_ioctl,
	owner:		THIS_MODULE
};

/*
 * module hooks
 */
module_init(dm_init);
module_exit(dm_exit);

MODULE_PARM(major, "i");
MODULE_PARM_DESC(major, "The major number of the device mapper");
MODULE_DESCRIPTION(DM_NAME " driver");
MODULE_AUTHOR("Joe Thornber <thornber@sistina.com>");
MODULE_LICENSE("GPL");
