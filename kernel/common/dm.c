/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "kcopyd.h"

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

static struct mapped_device *_devs[MAX_DEVICES];
static struct rw_semaphore _dev_locks[MAX_DEVICES];

/*
 * This lock is only held by dm_create and dm_set_name to avoid
 * race conditions where someone else may create a device with
 * the same name.
 */
static spinlock_t _create_lock = SPIN_LOCK_UNLOCKED;

/* block device arrays */
static int _block_size[MAX_DEVICES];
static int _blksize_size[MAX_DEVICES];
static int _hardsect_size[MAX_DEVICES];

static devfs_handle_t _dev_dir;

static int request(request_queue_t * q, int rw, struct buffer_head *bh);
static int dm_user_bmap(struct inode *inode, struct lv_bmap *lvb);

/*
 * Protect the mapped_devices referenced from _dev[]
 */
struct mapped_device *dm_get_r(int minor)
{
	struct mapped_device *md;

	if (minor >= MAX_DEVICES)
		return NULL;

	down_read(_dev_locks + minor);
	md = _devs[minor];
	if (!md)
		up_read(_dev_locks + minor);
	return md;
}

struct mapped_device *dm_get_w(int minor)
{
	struct mapped_device *md;

	if (minor >= MAX_DEVICES)
		return NULL;

	down_write(_dev_locks + minor);
	md = _devs[minor];
	if (!md)
		up_write(_dev_locks + minor);
	return md;
}

static int namecmp(struct mapped_device *md, const char *name, int nametype)
{
	switch (nametype) {
	case DM_LOOKUP_BY_NAME:
		return strcmp(md->name, name);
		break;

	case DM_LOOKUP_BY_UUID:
		if (!md->uuid)
			return -1;	/* never equal */

		return strcmp(md->uuid, name);
		break;

	default:
		DMWARN("Unknown comparison type in namecmp: %d", nametype);
		BUG();
	}

	return -1;
}

/*
 * The interface (eg, ioctl) will probably access the devices
 * through these slow 'by name' locks, this needs improving at
 * some point if people start playing with *large* numbers of dm
 * devices.
 */
struct mapped_device *dm_get_name_r(const char *name, int nametype)
{
	int i;
	struct mapped_device *md;

	for (i = 0; i < MAX_DEVICES; i++) {
		md = dm_get_r(i);
		if (md) {
			if (!namecmp(md, name, nametype))
				return md;

			dm_put_r(md);
		}
	}

	return NULL;
}

struct mapped_device *dm_get_name_w(const char *name, int nametype)
{
	int i;
	struct mapped_device *md;

	/*
	 * To avoid getting write locks on all the devices we try
	 * and promote a read lock to a write lock, this can
	 * fail, in which case we just start again.
	 */

      restart:
	for (i = 0; i < MAX_DEVICES; i++) {
		md = dm_get_r(i);
		if (!md)
			continue;

		if (namecmp(md, name, nametype)) {
			dm_put_r(md);
			continue;
		}

		/* found it */
		dm_put_r(md);

		md = dm_get_w(i);
		if (!md)
			goto restart;

		if (namecmp(md, name, nametype)) {
			dm_put_w(md);
			goto restart;
		}

		return md;
	}

	return NULL;
}

void dm_put_r(struct mapped_device *md)
{
	int minor = MINOR(md->dev);

	if (minor >= MAX_DEVICES)
		return;

	up_read(_dev_locks + minor);
}

void dm_put_w(struct mapped_device *md)
{
	int minor = MINOR(md->dev);

	if (minor >= MAX_DEVICES)
		return;

	up_write(_dev_locks + minor);
}

/*
 * Setup and tear down the driver
 */
static __init void init_locks(void)
{
	int i;

	for (i = 0; i < MAX_DEVICES; i++)
		init_rwsem(_dev_locks + i);
}

static __init int local_init(void)
{
	int r;

	init_locks();

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
	xx(dm_target)
	xx(dm_linear)
	xx(dm_stripe)
	xx(dm_snapshot)
	xx(dm_mirror)
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

	md = dm_get_w(MINOR(inode->i_rdev));
	if (!md)
		return -ENXIO;

	md->use_count++;
	dm_put_w(md);

	return 0;
}

static int dm_blk_close(struct inode *inode, struct file *file)
{
	struct mapped_device *md;

	md = dm_get_w(MINOR(inode->i_rdev));
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
	struct io_hook *ih = bh->b_bdev_private;

	if (!uptodate && call_err_fn(ih, bh))
		return;

	if (atomic_dec_and_test(&ih->md->pending))
		/* nudge anyone waiting on suspend queue */
		wake_up(&ih->md->wait);

	bh->b_end_io = ih->end_io;
	bh->b_bdev_private = ih->context;
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

	md = dm_get_w(MINOR(bh->b_rdev));
	if (!md) {
		free_deferred(di);
		return -ENXIO;
	}

	if (!md->suspended) {
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
	ih->context = bh->b_bdev_private;

	r = fn(bh, rw, context);

	if (r > 0) {
		/* hook the end io request fn */
		atomic_inc(&md->pending);
		bh->b_end_io = dec_pending;
		bh->b_bdev_private = ih;

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

static int request(request_queue_t * q, int rw, struct buffer_head *bh)
{
	struct mapped_device *md;
	int r, minor = MINOR(bh->b_rdev);
	unsigned int block_size = _blksize_size[minor];

	md = dm_get_r(minor);
	if (!md) {
		buffer_IO_error(bh);
		return 0;
	}

	/*
	 * Sanity checks.
	 */
	if (bh->b_size > block_size)
		DMERR("request is larger than block size "
		      "b_size (%d), block size (%d)",
		      bh->b_size, block_size);

	if (bh->b_rsector & ((bh->b_size >> 9) - 1))
		DMERR("misaligned block requested logical "
		      "sector (%lu), b_size (%d)",
		      bh->b_rsector, bh->b_size);

	/*
	 * If we're suspended we have to queue
	 * this io for later.
	 */
	while (md->suspended) {
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
		md = dm_get_r(minor);
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

static int check_dev_size(int minor, unsigned long block)
{
	/* FIXME: check this */
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
	int minor = MINOR(dev), r;
	struct target *t;

	md = dm_get_r(minor);
	if (!md)
		return -ENXIO;

	if (md->suspended) {
		dm_put_r(md);
		return -EPERM;
	}

	if (!check_dev_size(minor, block)) {
		dm_put_r(md);
		return -EINVAL;
	}

	/* setup dummy bh */
	memset(&bh, 0, sizeof(bh));
	bh.b_blocknr = block;
	bh.b_dev = bh.b_rdev = dev;
	bh.b_size = _blksize_size[minor];
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
 * See if the device with a specific minor # is free.  The write
 * lock is held when it returns successfully.
 */
static inline int specific_dev(int minor, struct mapped_device *md)
{
	if (minor >= MAX_DEVICES) {
		DMWARN("request for a mapped_device beyond MAX_DEVICES (%d)",
		       MAX_DEVICES);
		return -1;
	}

	down_write(_dev_locks + minor);
	if (_devs[minor]) {
		/* in use */
		up_write(_dev_locks + minor);
		return -1;
	}

	return minor;
}

/*
 * Find the first free device.  Again the write lock is held on
 * success.
 */
static int any_old_dev(struct mapped_device *md)
{
	int i;

	for (i = 0; i < MAX_DEVICES; i++)
		if (specific_dev(i, md) != -1)
			return i;

	return -1;
}

/*
 * Allocate and initialise a blank device.
 * Caller must ensure uuid is null-terminated.
 * Device is returned with a write lock held.
 */
static struct mapped_device *alloc_dev(const char *name, const char *uuid,
				       int minor)
{
	struct mapped_device *md = kmalloc(sizeof(*md), GFP_KERNEL);
	int len;

	if (!md) {
		DMWARN("unable to allocate device, out of memory.");
		return NULL;
	}

	memset(md, 0, sizeof(*md));

	/*
	 * This grabs the write lock if it succeeds.
	 */
	minor = (minor < 0) ? any_old_dev(md) : specific_dev(minor, md);
	if (minor < 0) {
		kfree(md);
		return NULL;
	}

	md->dev = MKDEV(_major, minor);
	md->suspended = 0;

	strncpy(md->name, name, sizeof(md->name) - 1);
	md->name[sizeof(md->name) - 1] = '\0';

	/*
	 * Copy in the uuid.
	 */
	if (uuid && *uuid) {
		len = strlen(uuid) + 1;
		if (!(md->uuid = kmalloc(len, GFP_KERNEL))) {
			DMWARN("unable to allocate uuid - out of memory.");
			kfree(md);
			return NULL;
		}
		strcpy(md->uuid, uuid);
	}

	init_waitqueue_head(&md->wait);
	return md;
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
 * The hardsect size for a mapped device is the smallest hardsect size
 * from the devices it maps onto.
 */
static int __find_hardsect_size(struct list_head *devices)
{
	int result = INT_MAX, size;
	struct list_head *tmp;

	list_for_each(tmp, devices) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);
		size = get_hardsect_size(dd->dev);
		if (size < result)
			result = size;
	}

	/*
	 * I think it's safe to assume that no block devices have
	 * a hard sector size this large.
	 */
	if (result == INT_MAX)
		result = 512;

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
	struct mapped_device *md;

	if (strchr(name, '/') || strlen(name) > DM_NAME_LEN) {
		DMWARN("invalid device name");
		return -1;
	}

	md = dm_get_name_r(name, DM_LOOKUP_BY_NAME);
	if (md) {
		dm_put_r(md);
		DMWARN("device name already in use");
		return -1;
	}

	return 0;
}

static int check_uuid(const char *uuid)
{
	struct mapped_device *md;

	if (uuid) {
		md = dm_get_name_r(uuid, DM_LOOKUP_BY_UUID);
		if (md) {
			dm_put_r(md);
			DMWARN("device uuid already in use");
			return -1;
		}
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

	spin_lock(&_create_lock);
	if (check_name(name) || check_uuid(uuid)) {
		spin_unlock(&_create_lock);
		return -EINVAL;
	}

	md = alloc_dev(name, uuid, minor);
	if (!md) {
		spin_unlock(&_create_lock);
		return -ENXIO;
	}
	minor = MINOR(md->dev);
	_devs[minor] = md;

	r = __register_device(md);
	if (r)
		goto err;

	r = __bind(md, table);
	if (r)
		goto err;

	dm_set_ro(md, ro);

	spin_unlock(&_create_lock);
	dm_put_w(md);
	return 0;

      err:
	_devs[minor] = NULL;
	if (md->uuid)
		kfree(md->uuid);

	dm_put_w(md);
	kfree(md);
	spin_unlock(&_create_lock);
	return r;
}

/*
 * Renames the device.  No lock held.
 */
int dm_set_name(const char *name, int nametype, const char *newname)
{
	int r;
	struct mapped_device *md;

	spin_lock(&_create_lock);
	if (check_name(newname) < 0) {
		spin_unlock(&_create_lock);
		return -EINVAL;
	}

	md = dm_get_name_w(name, nametype);
	if (!md) {
		spin_unlock(&_create_lock);
		return -ENXIO;
	}

	r = __unregister_device(md);
	if (r)
		goto out;

	strcpy(md->name, newname);
	r = __register_device(md);

      out:
	dm_put_w(md);
	spin_unlock(&_create_lock);
	return r;
}

/*
 * Destructor for the device.  You cannot destroy an open
 * device.  Write lock must be held before calling.
 * Caller must dm_put_w(md) then kfree(md) if call was successful.
 */
int dm_destroy(struct mapped_device *md)
{
	int minor, r;

	if (md->use_count)
		return -EPERM;

	r = __unregister_device(md);
	if (r)
		return r;

	minor = MINOR(md->dev);
	_devs[minor] = NULL;
	__unbind(md);

	if (md->uuid)
		kfree(md->uuid);

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
			md = dm_get_w(i);
			if (!md)
				continue;

			r = dm_destroy(md);
			dm_put_w(md);

			if (!r) {
				kfree(md);
				some_destroyed = 1;
			}
		}
	} while (some_destroyed);
}

/*
 * Sets or clears the read-only flag for the device.  Write lock
 * must be held.
 */
void dm_set_ro(struct mapped_device *md, int ro)
{
	md->read_only = ro;
	set_device_ro(md->dev, ro);
}

/*
 * A target is notifying us of some event
 */
void dm_notify(void *target)
{
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
	if (!md->suspended)
		return -EPERM;

	__unbind(md);

	r = __bind(md, table);
	if (r)
		return r;

	return 0;
}

/*
 * We need to be able to change a mapping table under a mounted
 * filesystem.  for example we might want to move some data in
 * the background.  Before the table can be swapped with
 * dm_bind_table, dm_suspend must be called to flush any in
 * flight buffer_heads and ensure that any further io gets
 * deferred.  Write lock must be held.
 */
int dm_suspend(struct mapped_device *md)
{
	int minor = MINOR(md->dev);
	DECLARE_WAITQUEUE(wait, current);

	if (md->suspended)
		return -EINVAL;

	md->suspended = 1;
	dm_put_w(md);

	/* wait for all the pending io to flush */
	add_wait_queue(&md->wait, &wait);
	current->state = TASK_UNINTERRUPTIBLE;
	do {
		md = dm_get_w(minor);
		if (!md) {
			/* Caller expects to free this lock. Yuck. */
			down_write(_dev_locks + minor);
			return -ENXIO;
		}

		if (!atomic_read(&md->pending))
			break;

		dm_put_w(md);
		schedule();

	} while (1);

	current->state = TASK_RUNNING;
	remove_wait_queue(&md->wait, &wait);

	return 0;
}

int dm_resume(struct mapped_device *md)
{
	int minor = MINOR(md->dev);
	struct deferred_io *def;

	if (!md->suspended || !md->map->num_targets)
		return -EINVAL;

	md->suspended = 0;
	def = md->deferred;
	md->deferred = NULL;

	dm_put_w(md);
	flush_deferred_io(def);
	run_task_queue(&tq_disk);

	if (!dm_get_w(minor)) {
		/* FIXME: yuck */
		down_write(_dev_locks + minor);
		return -ENXIO;
	}

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
