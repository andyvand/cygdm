/*
 * Copyright (C) 2001, 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/blk.h>
#include <linux/blkpg.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/kdev_t.h>
#include <linux/lvm.h>

#include <asm/uaccess.h>

static const char *_name = DM_NAME;
#define MAX_DEVICES (1 << MINORBITS)
#define DEFAULT_READ_AHEAD 64

static int major = 0;
static int _major = 0;

struct dm_io {
	struct mapped_device *md;

	struct dm_target *ti;
	int rw;
	void *map_context;
	void (*end_io) (struct buffer_head * bh, int uptodate);
	void *context;
};

struct deferred_io {
	int rw;
	struct buffer_head *bh;
	struct deferred_io *next;
};

/*
 * Bits for the md->flags field.
 */
#define DMF_BLOCK_IO 0
#define DMF_SUSPENDED 1

struct mapped_device {
	struct rw_semaphore lock;
	atomic_t holders;

	kdev_t dev;
	unsigned long flags;

	/*
	 * A list of ios that arrived while we were suspended.
	 */
	atomic_t pending;
	wait_queue_head_t wait;
	struct deferred_io *deferred;

	/*
	 * The current mapping.
	 */
	struct dm_table *map;

	/*
	 * io objects are allocated from here.
	 */
	mempool_t *io_pool;
};

#define MIN_IOS 256
static kmem_cache_t *_io_cache;

/* block device arrays */
static int _block_size[MAX_DEVICES];
static int _blksize_size[MAX_DEVICES];
static int _hardsect_size[MAX_DEVICES];

static struct mapped_device *get_kdev(kdev_t dev);
static int dm_request(request_queue_t *q, int rw, struct buffer_head *bh);
static int dm_user_bmap(struct inode *inode, struct lv_bmap *lvb);

static __init int local_init(void)
{
	int r;

	/* allocate a slab for the dm_ios */
	_io_cache = kmem_cache_create("dm io",
				      sizeof(struct dm_io), 0, 0, NULL, NULL);

	if (!_io_cache)
		return -ENOMEM;

	_major = major;
	r = register_blkdev(_major, _name, &dm_blk_dops);
	if (r < 0) {
		DMERR("register_blkdev failed");
		kmem_cache_destroy(_io_cache);
		return r;
	}

	if (!_major)
		_major = r;

	/* set up the arrays */
	read_ahead[_major] = DEFAULT_READ_AHEAD;
	blk_size[_major] = _block_size;
	blksize_size[_major] = _blksize_size;
	hardsect_size[_major] = _hardsect_size;

	blk_queue_make_request(BLK_DEFAULT_QUEUE(_major), dm_request);

	return 0;
}

static void local_exit(void)
{
	kmem_cache_destroy(_io_cache);

	if (unregister_blkdev(_major, _name) < 0)
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
	int (*init) (void);
	void (*exit) (void);

} _inits[] = {
#define xx(n) {n ## _init, n ## _exit},
	xx(local)
	xx(dm_target)
	xx(dm_linear)
	xx(dm_stripe)
	xx(dm_snapshot)
	xx(dm_interface)
#undef xx
};

static int __init dm_init(void)
{
	const int count = ARRAY_SIZE(_inits);

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
	int i = ARRAY_SIZE(_inits);

	while (i--)
		_inits[i].exit();
}

/*
 * Block device functions
 */
static int dm_blk_open(struct inode *inode, struct file *file)
{
	struct mapped_device *md;

	md = get_kdev(inode->i_rdev);
	if (!md)
		return -ENXIO;

	return 0;
}

static int dm_blk_close(struct inode *inode, struct file *file)
{
	struct mapped_device *md;

	md = get_kdev(inode->i_rdev);
	dm_put(md);		/* put the reference gained by dm_blk_open */
	dm_put(md);
	return 0;
}

static inline struct dm_io *alloc_io(struct mapped_device *md)
{
	return mempool_alloc(md->io_pool, GFP_NOIO);
}

static inline void free_io(struct mapped_device *md, struct dm_io *io)
{
	mempool_free(io, md->io_pool);
}

static inline struct deferred_io *alloc_deferred(void)
{
	return kmalloc(sizeof(struct deferred_io), GFP_NOIO);
}

static inline void free_deferred(struct deferred_io *di)
{
	kfree(di);
}

/* In 512-byte units */
#define VOLUME_SIZE(minor) (_block_size[(minor)] << 1)

/* FIXME: check this */
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

/*
 * Add the buffer to the list of deferred io.
 */
static int queue_io(struct mapped_device *md, struct buffer_head *bh, int rw)
{
	struct deferred_io *di;

	di = alloc_deferred();
	if (!di)
		return -ENOMEM;

	down_write(&md->lock);

	if (!test_bit(DMF_BLOCK_IO, &md->flags)) {
		up_write(&md->lock);
		free_deferred(di);
		return 1;
	}

	di->bh = bh;
	di->rw = rw;
	di->next = md->deferred;
	md->deferred = di;

	up_write(&md->lock);
	return 0;		/* deferred successfully */
}

/*
 * bh->b_end_io routine that decrements the pending count
 * and then calls the original bh->b_end_io fn.
 */
static void dec_pending(struct buffer_head *bh, int uptodate)
{
	int r;
	struct dm_io *io = bh->b_private;
	dm_endio_fn endio = io->ti->type->end_io;

	if (endio) {
		r = endio(io->ti, bh, io->rw, uptodate ? 0 : -EIO,
			  io->map_context);
		if (r < 0)
			uptodate = 0;

		else if (r > 0)
			/* the target wants another shot at the io */
			return;
	}

	if (atomic_dec_and_test(&io->md->pending))
		/* nudge anyone waiting on suspend queue */
		wake_up(&io->md->wait);

	bh->b_end_io = io->end_io;
	bh->b_private = io->context;
	free_io(io->md, io);

	bh->b_end_io(bh, uptodate);
}

/*
 * Do the bh mapping for a given leaf
 */
static inline int __map_buffer(struct mapped_device *md, int rw,
			       struct buffer_head *bh, struct dm_io *io)
{
	struct dm_target *ti;

	ti = dm_table_find_target(md->map, bh->b_rsector);
	if (!ti || !ti->type)
		return -EINVAL;

	/* hook the end io request fn */
	atomic_inc(&md->pending);
	io->md = md;
	io->ti = ti;
	io->rw = rw;
	io->end_io = bh->b_end_io;
	io->context = bh->b_private;
	bh->b_end_io = dec_pending;
	bh->b_private = io;

	return ti->type->map(ti, bh, rw, &io->map_context);
}

/*
 * Checks to see if we should be deferring io, if so it queues it
 * and returns 1.
 */
static inline int __deferring(struct mapped_device *md, int rw,
			      struct buffer_head *bh)
{
	int r;

	/*
	 * If we're suspended we have to queue this io for later.
	 */
	while (test_bit(DMF_BLOCK_IO, &md->flags)) {
		up_read(&md->lock);

		/*
		 * There's no point deferring a read ahead
		 * request, just drop it.
		 */
		if (rw == READA) {
			down_read(&md->lock);
			return -EIO;
		}

		r = queue_io(md, bh, rw);
		down_read(&md->lock);

		if (r < 0)
			return r;

		if (r == 0)
			return 1; /* deferred successfully */

	}

	return 0;
}

static int dm_request(request_queue_t *q, int rw, struct buffer_head *bh)
{
	int r;
	struct dm_io *io;
	struct mapped_device *md;

	md = get_kdev(bh->b_rdev);
	if (!md) {
		buffer_IO_error(bh);
		return 0;
	}

	io = alloc_io(md);
	down_read(&md->lock);

	r = __deferring(md, rw, bh);
	if (r < 0)
		goto bad;

	else if (!r) {
		/* not deferring */
		r = __map_buffer(md, rw, bh, io);
		if (r < 0)
			goto bad;
	} else
		r = 0;

	up_read(&md->lock);
	dm_put(md);
	return r;

      bad:
	buffer_IO_error(bh);
	up_read(&md->lock);
	dm_put(md);
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
static int __bmap(struct mapped_device *md, kdev_t dev, unsigned long block,
		  kdev_t *r_dev, unsigned long *r_block)
{
	struct buffer_head bh;
	struct dm_target *ti;
	void *map_context;
	int r;

	if (test_bit(DMF_BLOCK_IO, &md->flags)) {
		return -EPERM;
	}

	if (!check_dev_size(dev, block)) {
		return -EINVAL;
	}

	/* setup dummy bh */
	memset(&bh, 0, sizeof(bh));
	bh.b_blocknr = block;
	bh.b_dev = bh.b_rdev = dev;
	bh.b_size = _blksize_size[MINOR(dev)];
	bh.b_rsector = block * (bh.b_size >> 9);

	/* find target */
	ti = dm_table_find_target(md->map, bh.b_rsector);

	/* do the mapping */
	r = ti->type->map(ti, &bh, READ, &map_context);
	ti->type->end_io(ti, &bh, READ, 0, map_context);

	if (!r) {
		*r_dev = bh.b_rdev;
		*r_block = bh.b_rsector / (bh.b_size >> 9);
	}

	return r;
}

/*
 * Marshals arguments and results between user and kernel space.
 */
static int dm_user_bmap(struct inode *inode, struct lv_bmap *lvb)
{
	struct mapped_device *md;
	unsigned long block, r_block;
	kdev_t r_dev;
	int r;

	if (get_user(block, &lvb->lv_block))
		return -EFAULT;

	md = get_kdev(inode->i_rdev);
	if (!md)
		return -ENXIO;

	down_read(&md->lock);
	r = __bmap(md, inode->i_rdev, block, &r_dev, &r_block);
	up_read(&md->lock);
	dm_put(md);

	if (!r && (put_user(kdev_t_to_nr(r_dev), &lvb->lv_dev) ||
		   put_user(r_block, &lvb->lv_block)))
		r = -EFAULT;

	return r;
}

/*-----------------------------------------------------------------
 * A bitset is used to keep track of allocated minor numbers.
 *---------------------------------------------------------------*/
static spinlock_t _minor_lock = SPIN_LOCK_UNLOCKED;
static struct mapped_device *_mds[MAX_DEVICES];

static void free_minor(int minor)
{
	spin_lock(&_minor_lock);
	_mds[minor] = NULL;
	spin_unlock(&_minor_lock);
}

/*
 * See if the device with a specific minor # is free.
 */
static int specific_minor(int minor, struct mapped_device *md)
{
	int r = -EBUSY;

	if (minor >= MAX_DEVICES) {
		DMWARN("request for a mapped_device beyond MAX_DEVICES (%d)",
		       MAX_DEVICES);
		return -EINVAL;
	}

	spin_lock(&_minor_lock);
	if (!_mds[minor]) {
		_mds[minor] = md;
		r = minor;
	}
	spin_unlock(&_minor_lock);

	return r;
}

static int next_free_minor(struct mapped_device *md)
{
	int i;

	spin_lock(&_minor_lock);
	for (i = 0; i < MAX_DEVICES; i++) {
		if (!_mds[i]) {
			_mds[i] = md;
			break;
		}
	}
	spin_unlock(&_minor_lock);

	return (i < MAX_DEVICES) ? i : -EBUSY;
}

static struct mapped_device *get_kdev(kdev_t dev)
{
	struct mapped_device *md;

	if (major(dev) != _major)
		return NULL;

	spin_lock(&_minor_lock);
	md = _mds[minor(dev)];
	if (md)
		dm_get(md);
	spin_unlock(&_minor_lock);

	return md;
}

/*
 * Allocate and initialise a blank device with a given minor.
 */
static struct mapped_device *alloc_dev(int minor)
{
	struct mapped_device *md = kmalloc(sizeof(*md), GFP_KERNEL);

	if (!md) {
		DMWARN("unable to allocate device, out of memory.");
		return NULL;
	}

	/* get a minor number for the dev */
	minor = (minor < 0) ? next_free_minor(md) : specific_minor(minor, md);
	if (minor < 0) {
		kfree(md);
		return NULL;
	}

	memset(md, 0, sizeof(*md));

	md->io_pool = mempool_create(MIN_IOS, mempool_alloc_slab,
				     mempool_free_slab, _io_cache);
	if (!md->io_pool) {
		free_minor(minor);
		kfree(md);
		return NULL;
	}

	md->dev = mk_kdev(_major, minor);
	init_rwsem(&md->lock);
	atomic_set(&md->holders, 1);
	atomic_set(&md->pending, 0);
	init_waitqueue_head(&md->wait);

	return md;
}

static void free_dev(struct mapped_device *md)
{
	free_minor(minor(md->dev));
	mempool_destroy(md->io_pool);
	kfree(md);
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
	int minor = minor(md->dev);
	md->map = t;

	/* in k */
	_block_size[minor] = dm_table_get_size(t) >> 1;
	_blksize_size[minor] = BLOCK_SIZE;
	_hardsect_size[minor] = __find_hardsect_size(dm_table_get_devices(t));
	register_disk(NULL, md->dev, 1, &dm_blk_dops, _block_size[minor]);

	dm_table_get(t);
	return 0;
}

static void __unbind(struct mapped_device *md)
{
	int minor = minor(md->dev);

	dm_table_put(md->map);
	md->map = NULL;

	_block_size[minor] = 0;
	_blksize_size[minor] = 0;
	_hardsect_size[minor] = 0;
}

/*
 * Constructor for a new device.
 */
int dm_create(int minor, struct dm_table *table, struct mapped_device **result)
{
	int r;
	struct mapped_device *md;

	md = alloc_dev(minor);
	if (!md)
		return -ENXIO;

	r = __bind(md, table);
	if (r) {
		free_dev(md);
		return r;
	}

	*result = md;
	return 0;
}

void dm_get(struct mapped_device *md)
{
	atomic_inc(&md->holders);
}

void dm_put(struct mapped_device *md)
{
	if (atomic_dec_and_test(&md->holders)) {
		__unbind(md);
		free_dev(md);
	}
}

/*
 * Requeue the deferred io by calling generic_make_request.
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
 * Swap in a new table (destroying old one).
 */
int dm_swap_table(struct mapped_device *md, struct dm_table *table)
{
	int r;

	down_write(&md->lock);

	/* device must be suspended */
	if (!test_bit(DMF_SUSPENDED, &md->flags)) {
		up_write(&md->lock);
		return -EPERM;
	}

	__unbind(md);
	r = __bind(md, table);
	if (r)
		return r;

	up_write(&md->lock);
	return 0;
}

/*
 * We need to be able to change a mapping table under a mounted
 * filesystem.  For example we might want to move some data in
 * the background.  Before the table can be swapped with
 * dm_bind_table, dm_suspend must be called to flush any in
 * flight io and ensure that any further io gets deferred.
 */
int dm_suspend(struct mapped_device *md)
{
	DECLARE_WAITQUEUE(wait, current);

	down_write(&md->lock);

	/*
	 * First we set the BLOCK_IO flag so no more ios will be
	 * mapped.
	 */
	if (test_bit(DMF_BLOCK_IO, &md->flags)) {
		up_write(&md->lock);
		return -EINVAL;
	}

	set_bit(DMF_BLOCK_IO, &md->flags);
	add_wait_queue(&md->wait, &wait);
	up_write(&md->lock);

	/*
	 * Then we wait for the already mapped ios to
	 * complete.
	 */
	run_task_queue(&tq_disk);
	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);

		if (!atomic_read(&md->pending))
			break;

		schedule();
	}

	current->state = TASK_RUNNING;

	down_write(&md->lock);
	remove_wait_queue(&md->wait, &wait);
	set_bit(DMF_SUSPENDED, &md->flags);
	up_write(&md->lock);

	return 0;
}

int dm_resume(struct mapped_device *md)
{
	struct deferred_io *def;

	down_write(&md->lock);
	if (!test_bit(DMF_SUSPENDED, &md->flags) ||
	    !dm_table_get_size(md->map)) {
		up_write(&md->lock);
		return -EINVAL;
	}

	clear_bit(DMF_SUSPENDED, &md->flags);
	clear_bit(DMF_BLOCK_IO, &md->flags);
	def = md->deferred;
	md->deferred = NULL;
	up_write(&md->lock);

	flush_deferred_io(def);
	run_task_queue(&tq_disk);

	return 0;
}

struct dm_table *dm_get_table(struct mapped_device *md)
{
	struct dm_table *t;

	down_read(&md->lock);
	t = md->map;
	dm_table_get(t);
	up_read(&md->lock);

	return t;
}

kdev_t dm_kdev(struct mapped_device *md)
{
	kdev_t dev;

	down_read(&md->lock);
	dev = md->dev;
	up_read(&md->lock);

	return dev;
}

int dm_suspended(struct mapped_device *md)
{
	return test_bit(DMF_SUSPENDED, &md->flags);
}

struct block_device_operations dm_blk_dops = {
	.open = dm_blk_open,
	.release = dm_blk_close,
	.ioctl = dm_blk_ioctl,
	.owner = THIS_MODULE
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
