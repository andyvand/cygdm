/*
 * dm-snapshot.c
 *
 * Copyright (C) 2001-2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/mempool.h>
#include <linux/device-mapper.h>

#include "dm-snapshot.h"

/*
 * Hard sector size used all over the kernel
 */
#define SECTOR_SIZE 512

/*
 * kcopyd priority of snapshot operations
 */
#define SNAPSHOT_COPY_PRIORITY 2

struct pending_exception {
	struct exception e;

	/* Chain of WRITE buffer heads to submit when this COW has completed */
	struct buffer_head *origin_buffers;
	struct buffer_head *snapshot_buffers;

	/* Pointer back to snapshot context */
	struct dm_snapshot *snap;
};

/*
 * Hash table mapping origin volumes to lists of snapshots and
 * a lock to protect it
 */
static kmem_cache_t *exception_cachep;
static kmem_cache_t *pending_cachep;
static mempool_t *pending_pool;

/*
 * One of these per registered origin, held in the snapshot_origins hash
 */
struct origin {
	/* The origin device */
	kdev_t dev;

	struct list_head hash_list;

	/* List of snapshots for this origin */
	struct list_head snapshots;
};

/*
 * Useful macro for running the store functions.  Use store_int_fn if you want the return value.
 */
#define store_fn(snap, fn, args...) \
    if ((snap)->store. ## fn) \
        (snap)->store. ## fn ( &(snap)->store , ## args )

#define store_int_fn(snap, fn, args...) \
    (((snap)->store. ## fn) ? \
        ((snap)->store. ## fn ( &(snap)->store , ## args )) : 0)

/*
 * Size of the hash table for origin volumes. If we make this
 * the size of the minors list then it should be nearly perfect
 */
#define ORIGIN_HASH_SIZE 256
#define ORIGIN_MASK      0xFF
static struct list_head *_origins;
static struct rw_semaphore _origins_lock;

static int init_origin_hash(void)
{
	int i;

	_origins = kmalloc(ORIGIN_HASH_SIZE * sizeof(struct list_head),
			   GFP_KERNEL);
	if (!_origins) {
		DMERR("Device mapper: Snapshot: unable to allocate memory");
		return -ENOMEM;
	}

	for (i = 0; i < ORIGIN_HASH_SIZE; i++)
		INIT_LIST_HEAD(_origins + i);
	init_rwsem(&_origins_lock);

	return 0;
}

static void exit_origin_hash(void)
{
	kfree(_origins);
}

static inline unsigned int origin_hash(kdev_t dev)
{
	return MINOR(dev) & ORIGIN_MASK;
}

static struct origin *__lookup_origin(kdev_t origin)
{
	struct list_head *slist;
	struct list_head *ol;
	struct origin *o;

	ol = &_origins[origin_hash(origin)];
	list_for_each(slist, ol) {
		o = list_entry(slist, struct origin, hash_list);

		if (o->dev == origin)
			return o;
	}

	return NULL;
}

static void __insert_origin(struct origin *o)
{
	struct list_head *sl = &_origins[origin_hash(o->dev)];
	list_add_tail(&o->hash_list, sl);
}

/*
 * Make a note of the snapshot and its origin so we can look it
 * up when the origin has a write on it.
 */
static int register_snapshot(struct dm_snapshot *snap)
{
	struct origin *o;
	kdev_t dev = snap->origin->dev;

	down_write(&_origins_lock);
	o = __lookup_origin(dev);

	if (!o) {
		/* New origin */
		o = kmalloc(sizeof(*o), GFP_KERNEL);
		if (!o) {
			up_write(&_origins_lock);
			return -ENOMEM;
		}

		/* Initialise the struct */
		INIT_LIST_HEAD(&o->snapshots);
		o->dev = dev;

		__insert_origin(o);
	}

	list_add_tail(&snap->list, &o->snapshots);

	up_write(&_origins_lock);
	return 0;
}

static void unregister_snapshot(struct dm_snapshot *s)
{
	struct origin *o;

	down_write(&_origins_lock);
	o = __lookup_origin(s->origin->dev);

	list_del(&s->list);
	if (list_empty(&o->snapshots)) {
		list_del(&o->hash_list);
		kfree(o);
	}

	up_write(&_origins_lock);
}

/*
 * Implementation of the exception hash tables.
 */
static int init_exception_table(struct exception_table *et, uint32_t size)
{
	int i;

	et->hash_mask = size - 1;
	et->table = vmalloc(sizeof(struct list_head) * (size));
	if (!et->table)
		return -ENOMEM;

	for (i = 0; i < size; i++)
		INIT_LIST_HEAD(et->table + i);

	return 0;
}

static void exit_exception_table(struct exception_table *et, kmem_cache_t *mem)
{
	struct list_head *slot, *entry, *temp;
	struct exception *ex;
	int i, size;

	size = et->hash_mask + 1;
	for (i = 0; i < size; i++) {
		slot = et->table + i;

		list_for_each_safe(entry, temp, slot) {
			ex = list_entry(entry, struct exception, hash_list);
			kmem_cache_free(mem, ex);
		}
	}

	vfree(et->table);
}

/*
 * FIXME: check how this hash fn is performing.
 */
static inline uint32_t exception_hash(struct exception_table *et, chunk_t chunk)
{
	return chunk & et->hash_mask;
}

static void insert_exception(struct exception_table *eh, struct exception *e)
{
	struct list_head *l = &eh->table[exception_hash(eh, e->old_chunk)];
	list_add(&e->hash_list, l);
}

static inline void remove_exception(struct exception *e)
{
	list_del(&e->hash_list);
}

/*
 * Return the exception data for a sector, or NULL if not
 * remapped.
 */
static struct exception *lookup_exception(struct exception_table *et,
					  chunk_t chunk)
{
	struct list_head *slot, *el;
	struct exception *e;

	slot = &et->table[exception_hash(et, chunk)];
	list_for_each(el, slot) {
		e = list_entry(el, struct exception, hash_list);
		if (e->old_chunk == chunk)
			return e;
	}

	return NULL;
}

void *pool_alloc_pending(int gfp_mask, void *pool_data)
{
	kmem_cache_t *mem = (kmem_cache_t *) pool_data;
	return kmem_cache_alloc(mem, gfp_mask);
}

void pool_free_pending(void *element, void *pool_data)
{
	kmem_cache_t *mem = (kmem_cache_t *) pool_data;
	kmem_cache_free(mem, element);
}

static inline struct pending_exception *alloc_pending_exception(void)
{
	return mempool_alloc(pending_pool, GFP_NOIO);
}

static inline void free_pending_exception(struct pending_exception *pe)
{
	mempool_free(pe, pending_pool);
}

static inline struct exception *alloc_exception(void)
{
	return kmem_cache_alloc(exception_cachep, GFP_NOIO);
}

static inline void free_exception(struct exception *e)
{
	kmem_cache_free(exception_cachep, e);
}

int dm_add_exception(struct dm_snapshot *s, chunk_t old, chunk_t new)
{
	struct exception *e;

	e = alloc_exception();
	if (!e)
		return -ENOMEM;

	e->old_chunk = old;
	e->new_chunk = new;
	insert_exception(&s->complete, e);
	return 0;
}

/*
 * Hard coded magic.
 */
static int calc_max_buckets(void)
{
	unsigned long mem;

	mem = num_physpages << PAGE_SHIFT;
	mem /= 50;
	mem /= sizeof(struct list_head);

	return mem;
}

/*
 * Rounds a number down to a power of 2.
 */
static inline uint32_t round_down(uint32_t n)
{
	while (n & (n - 1))
		n &= (n - 1);
	return n;
}

/*
 * Allocate room for a suitable hash table.
 */
static int init_hash_tables(struct dm_snapshot *s)
{
	offset_t hash_size, cow_dev_size, origin_dev_size, max_buckets;

	/*
	 * Calculate based on the size of the original volume or
	 * the COW volume...
	 */
	cow_dev_size = get_dev_size(s->cow->dev);
	origin_dev_size = get_dev_size(s->origin->dev);
	max_buckets = calc_max_buckets();

	hash_size = min(origin_dev_size, cow_dev_size) / s->chunk_size;
	hash_size = min(hash_size, max_buckets);

	/* Round it down to a power of 2 */
	hash_size = round_down(hash_size);
	if (init_exception_table(&s->complete, hash_size))
		return -ENOMEM;

	/*
	 * Allocate hash table for in-flight exceptions
	 * Make this smaller than the real hash table
	 */
	hash_size >>= 3;
	if (!hash_size)
		hash_size = 64;

	if (init_exception_table(&s->pending, hash_size)) {
		exit_exception_table(&s->complete, exception_cachep);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Construct a snapshot mapping: <origin_dev> <COW-dev> <p/n>
 * <chunk-size> <extent-size>
 */
static int snapshot_ctr(struct dm_table *t, offset_t b, offset_t l,
			int argc, char **argv, void **context)
{
	struct dm_snapshot *s;
	unsigned long chunk_size;
	unsigned long extent_size = 0L;
	int r = -EINVAL;
	char *persistent;
	char *origin_path;
	char *cow_path;
	char *value;
	int blocksize;

	if (argc < 4) {
		*context = "dm-snapshot: Not enough arguments";
		r = -EINVAL;
		goto bad;
	}

	origin_path = argv[0];
	cow_path = argv[1];
	persistent = argv[2];

	if ((*persistent & 0x5f) != 'P' && (*persistent & 0x5f) != 'N') {
		*context = "Persistent flag is not P or N";
		r = -EINVAL;
		goto bad;
	}

	chunk_size = simple_strtoul(argv[3], &value, 10);
	if (chunk_size == 0 || value == NULL) {
		*context = "Invalid chunk size";
		r = -EINVAL;
		goto bad;
	}

	/* Get the extent size for persistent snapshots */
	if ((*persistent & 0x5f) == 'P') {
		if (argc < 5) {
			*context = "No extent size specified";
			r = -EINVAL;
			goto bad;
		}

		extent_size = simple_strtoul(argv[4], &value, 10);
		if (extent_size == 0 || value == NULL) {
			*context = "Invalid extent size";
			r = -EINVAL;
			goto bad;
		}
	}

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (s == NULL) {
		*context = "Cannot allocate snapshot context private structure";
		r = -ENOMEM;
		goto bad;
	}

	r = dm_table_get_device(t, origin_path, 0, 0, &s->origin);
	if (r) {
		*context = "Cannot get origin device";
		goto bad_free;
	}

	r = dm_table_get_device(t, cow_path, 0, 0, &s->cow);
	if (r) {
		dm_table_put_device(t, s->origin);
		*context = "Cannot get COW device";
		goto bad_free;
	}

	/* Validate the extent and chunk sizes against the device block size */
	blocksize = get_hardsect_size(s->cow->dev);
	if (chunk_size % (blocksize / SECTOR_SIZE)) {
		*context = "Chunk size is not a multiple of device blocksize";
		r = -EINVAL;
		goto bad_putdev;
	}

	if (extent_size % (blocksize / SECTOR_SIZE)) {
		*context = "Extent size is not a multiple of device blocksize";
		r = -EINVAL;
		goto bad_putdev;
	}

	/* Check the sizes are small enough to fit in one kiovec */
	if (chunk_size > KIO_MAX_SECTORS) {
		*context = "Chunk size is too big";
		r = -EINVAL;
		goto bad_putdev;
	}

	if (extent_size > KIO_MAX_SECTORS) {
		*context = "Extent size is too big";
		r = -EINVAL;
		goto bad_putdev;
	}

	/* Check chunk_size is a power of 2 */
	if (chunk_size & (chunk_size - 1)) {
		*context = "Chunk size is not a power of 2";
		r = -EINVAL;
		goto bad_putdev;
	}

	s->chunk_size = chunk_size;
	s->chunk_mask = chunk_size - 1;
	for (s->chunk_shift = 0; chunk_size;
	     s->chunk_shift++, chunk_size >>= 1)
		;
	s->chunk_shift--;

	s->valid = 1;
	init_rwsem(&s->lock);

	/* Allocate hash table for COW data */
	if (init_hash_tables(s)) {
		*context = "Unable to allocate hash table space";
		r = -ENOMEM;
		goto bad_putdev;
	}

	/*
	 * Check the persistent flag - done here because we need the iobuf
	 * to check the LV header
	 */
	/*AGKAGKAGKif ((*persistent & 0x5f) == 'P')
		r = dm_create_persistent(&s->store, s, blocksize,
					 extent_size, context);
	else */
		r = dm_create_transient(&s->store, s, blocksize, context);

	if (r) {
		*context = "Couldn't create exception store";
		r = -EINVAL;
		goto bad_free1;
	}

	/* Allocate the COW iobuf and set associated variables */
	r = store_int_fn(s, init, blocksize, extent_size, context);
	if (r) {
		*context = "Couldn't initialise exception store";
		goto bad_free1;
	}

	/* Flush IO to the origin device */
	/* FIXME: what does sct have against fsync_dev ? */
	fsync_dev(s->origin->dev);
#if LVM_VFS_ENHANCEMENT
	fsync_dev_lockfs(s->origin->dev);
#endif

	/* Add snapshot to the list of snapshots for this origin */
	if (register_snapshot(s)) {
		r = -EINVAL;
		*context = "Cannot register snapshot origin";
		goto bad_free2;
	}

#if LVM_VFS_ENHANCEMENT
	unlockfs(s->origin->dev);
#endif

	*context = s;
	return 0;

 bad_free2:
	store_fn(s, destroy);

 bad_free1:
	exit_exception_table(&s->pending, pending_cachep);
	exit_exception_table(&s->complete, exception_cachep);

 bad_putdev:
	dm_table_put_device(t, s->cow);
	dm_table_put_device(t, s->origin);

 bad_free:
	kfree(s);

 bad:
	return r;
}

static void snapshot_dtr(struct dm_table *t, void *context)
{
	struct dm_snapshot *s = (struct dm_snapshot *) context;

	unregister_snapshot(s);

	exit_exception_table(&s->pending, pending_cachep);
	exit_exception_table(&s->complete, exception_cachep);

	/* Deallocate memory used */
	store_fn(s, destroy);

	dm_table_put_device(t, s->origin);
	dm_table_put_device(t, s->cow);
	kfree(s);
}

/*
 * Flush a list of pending writes, that were waiting for an
 * exception.
 */
static void flush_buffers(struct buffer_head *bh)
{
	struct buffer_head *n;

	while (bh) {
		n = bh->b_reqnext;
		bh->b_reqnext = NULL;
		generic_make_request(WRITE, bh);
		bh = n;
	}
}

/*
 * Error a list of buffers.
 */
static void error_buffers(struct buffer_head *bh)
{
	struct buffer_head *n;

	while (bh) {
		n = bh->b_reqnext;
		bh->b_reqnext = NULL;
		buffer_IO_error(bh);
		bh = n;
	}
}

/*
 * Called when the copy I/O has finished
 */
static void copy_callback(copy_cb_reason_t reason, void *context, long arg)
{
	struct pending_exception *pe = (struct pending_exception *) context;
	struct dm_snapshot *s = pe->snap;
	struct exception *e;
	struct buffer_head *origin_bh, *snapshot_bh;

	switch (reason) {
	case COPY_CB_COMPLETE:
		/* Update the metadata if we are persistent */
		store_fn(s, commit_exception, &pe->e);

		e = alloc_exception();
		if (!e) {
			/* FIXME: what do we do now ? */
			return;
		}

		/*
		 * Add a proper exception, and remove the
		 * inflight exception from the list.
		 */
		down_write(&pe->snap->lock);

		memcpy(e, &pe->e, sizeof(*e));
		insert_exception(&s->complete, e);
		remove_exception(&pe->e);

		/* Submit any pending write BHs */
		origin_bh = pe->origin_buffers;
		snapshot_bh = pe->snapshot_buffers;
		up_write(&pe->snap->lock);

		free_pending_exception(pe);
		flush_buffers(origin_bh);
		flush_buffers(snapshot_bh);
		DMWARN("Exception completed successfully.");
		break;

	case COPY_CB_FAILED_WRITE:
	case COPY_CB_FAILED_READ:
		/* Read/write error - snapshot is unusable */
		DMERR("Error reading/writing snapshot");

		down_write(&pe->snap->lock);
		store_fn(pe->snap, drop_snapshot);
		pe->snap->valid = 0;
		origin_bh = pe->origin_buffers;
		snapshot_bh = pe->snapshot_buffers;
		remove_exception(&pe->e);
		up_write(&pe->snap->lock);

		free_pending_exception(pe);
		flush_buffers(origin_bh);
		error_buffers(snapshot_bh);
		DMWARN("Exception failed.");
		break;

	default:
		DMWARN("Unknown kcopyd callback reason.");
		BUG();
	}
}

/*
 * Inserts the buffer head on the correct queue, depending
 * whether its a snapshot or origin buffer.
 */
static void queue_buffer(struct pending_exception *pe,
			 struct buffer_head *bh,
			 int snapshot_buffer)
{
	struct buffer_head **bh_list;

	bh_list = snapshot_buffer ? &pe->snapshot_buffers :
		&pe->origin_buffers;

	bh->b_reqnext = *bh_list;
	*bh_list = bh;
}

/*
 * Performs a new copy on write.
 */
static int new_exception(struct dm_snapshot *s, struct buffer_head *bh,
			 int snapshot_buffer)
{
	struct exception *e;
	struct pending_exception *pe;
	chunk_t chunk;

	chunk = sector_to_chunk(s, bh->b_rsector);

	/*
	 * If the exception is in flight then we just defer the
	 * bh until this copy has completed.
	 */
	e = lookup_exception(&s->pending, chunk);
	if (e) {
		/* cast the exception to a pending exception */
		pe = list_entry(e, struct pending_exception, e);
		queue_buffer(pe, bh, snapshot_buffer);

	} else {
		/* Create a new pending exception */
		pe = alloc_pending_exception();
		if (!pe) {
			DMWARN("Couldn't allocate pending exception.");
			return -ENOMEM;
		}

		pe->e.old_chunk = chunk;
		pe->snap = s;
		pe->origin_buffers = pe->snapshot_buffers = NULL;
		queue_buffer(pe, bh, snapshot_buffer);

		if (store_int_fn(s, prepare_exception, &pe->e)) {
			free_pending_exception(pe);
			s->valid = 0;
			return -ENXIO;
		}

		insert_exception(&s->pending, &pe->e);

		/* Get kcopyd to do the copy */
		dm_blockcopy(chunk_to_sector(s, pe->e.old_chunk),
			     chunk_to_sector(s, pe->e.new_chunk),
			     s->chunk_size,
			     s->origin->dev,
			     s->cow->dev, SNAPSHOT_COPY_PRIORITY, 0,
			     copy_callback, pe);
	}

	return 0;
}

static inline void remap_exception(struct dm_snapshot *s, struct exception *e,
				   struct buffer_head *bh)
{
	bh->b_rdev = s->cow->dev;
	bh->b_rsector = chunk_to_sector(s, e->new_chunk) +
	    (bh->b_rsector & s->chunk_mask);
}

static int snapshot_map(struct buffer_head *bh, int rw, void *context)
{
	struct exception *e;
	struct dm_snapshot *s = (struct dm_snapshot *) context;
	int r = 1;
	chunk_t chunk;

	chunk = sector_to_chunk(s, bh->b_rsector);

	/* Full snapshots are not usable */
	if (!s->valid)
		return -1;

	/*
	 * Write to snapshot - higher level takes care of RW/RO
	 * flags so we should only get this if we are
	 * writeable.
	 */
	if (rw == WRITE) {

		down_write(&s->lock);

		/* If the block is already remapped - use that, else remap it */
		e = lookup_exception(&s->complete, chunk);
		if (e)
			remap_exception(s, e, bh);

		else {
			r = new_exception(s, bh, 1);

			if (r < 0) {
				store_fn(s, drop_snapshot);
				s->valid = 0;
			}
		}

		up_write(&s->lock);

	} else {
		/*
		 * FIXME: this read path scares me because we
		 * always use the origin when we have a pending
		 * exception.  However I can't think of a
		 * situation where this is wrong - ejt.
		 */

		/* Do reads */
		down_read(&s->lock);

		/* See if it it has been remapped */
		e = lookup_exception(&s->complete, chunk);
		if (e)
			remap_exception(s, e, bh);
		else
			bh->b_rdev = s->origin->dev;

		up_read(&s->lock);
	}

	return r;
}

static int __origin_write(struct list_head *snapshots, struct buffer_head *bh)
{
	int r = 1;
	struct list_head *sl;
	struct dm_snapshot *snap;
	struct exception *e;
	chunk_t chunk;

	/* Do all the snapshots on this origin */
	list_for_each(sl, snapshots) {
		snap = list_entry(sl, struct dm_snapshot, list);

		down_write(&snap->lock);

		/*
		 * Remember, different snapshots can have
		 * different chunk sizes.
		 */
		chunk = sector_to_chunk(snap, bh->b_rsector);

		/* Only deal with valid snapshots */
		if (snap->valid) {
			/*
			 * Check exception table to see if block
			 * is already remapped in this snapshot
			 * and trigger an exception if not.
			 */
			e = lookup_exception(&snap->complete, chunk);
			if (!e) {
				int lr;

				lr = new_exception(snap, bh, 1);
				if (lr < 0) {
					store_fn(snap, drop_snapshot);
					snap->valid = 0;

				} else if (lr == 0)
					r = 0; /* we must wait */
			}
		}

		up_write(&snap->lock);
	}

	return r;
}

/*
 * Called on a write from the origin driver.
 */
int do_origin(struct dm_dev *origin, struct buffer_head *bh)
{
	struct origin *o;
	int r;

	down_read(&_origins_lock);
	o = __lookup_origin(origin->dev);
	if (!o)
		BUG();

	r = __origin_write(&o->snapshots, bh);
	up_read(&_origins_lock);

	return r;
}


/*
 * Origin: maps a linear range of a device, with hooks for snapshotting.
 */

/*
 * Construct an origin mapping: <dev_path>
 * The context for an origin is merely a 'struct dm_dev *'
 * pointing to the real device.
 */
static int origin_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	int r;
	struct dm_dev *dev;

	if (argc != 1) {
		*context = "dm-origin: incorrect number of arguments";
		return -EINVAL;
	}

	r = dm_table_get_device(t, argv[0], 0, l, &dev);
	if (r) {
		*context = "Cannot get target device";
		return r;
	}

	*context = dev;

	return 0;
}

static void origin_dtr(struct dm_table *t, void *c)
{
	struct dm_dev *dev = (struct dm_dev *) c;
	dm_table_put_device(t, dev);
}

static int origin_map(struct buffer_head *bh, int rw, void *context)
{
	struct dm_dev *dev = (struct dm_dev *) context;
	bh->b_rdev = dev->dev;

	/* Only tell snapshots if this is a write */
	return (rw == WRITE) ? do_origin(dev, bh) : 1;
}

static struct target_type origin_target = {
	name:	"snapshot-origin",
	module:	THIS_MODULE,
	ctr:	origin_ctr,
	dtr:	origin_dtr,
	map:	origin_map,
	err:	NULL
};

static struct target_type snapshot_target = {
	name:"snapshot",
	module:THIS_MODULE,
	ctr:snapshot_ctr,
	dtr:snapshot_dtr,
	map:snapshot_map,
	err:NULL
};

int __init dm_snapshot_init(void)
{
	int r;

	r = dm_register_target(&snapshot_target);
	if (r) {
		DMERR("snapshot target register failed %d", r);
		return r;
	}

	r = dm_register_target(&origin_target);
	if (r < 0) {
		DMERR("Device mapper: Origin: register failed %d\n", r);
		goto bad1;
	}

	r = init_origin_hash();
	if (r) {
		DMERR("init_origin_hash failed.");
		goto bad2;
	}

	exception_cachep = kmem_cache_create("dm-snapshot-ex",
					     sizeof(struct exception),
					     __alignof__(struct exception),
					     0, NULL, NULL);
	if (!exception_cachep) {
		DMERR("Couldn't create exception cache.");
		r = -ENOMEM;
		goto bad3;
	}

	pending_cachep =
	    kmem_cache_create("dm-snapshot-in",
			      sizeof(struct pending_exception),
			      __alignof__(struct pending_exception),
			      0, NULL, NULL);
	if (!pending_cachep) {
		DMERR("Couldn't create pending cache.");
		r = -ENOMEM;
		goto bad4;
	}

	pending_pool = mempool_create(128, pool_alloc_pending,
				      pool_free_pending, pending_cachep);
	if (!pending_pool) {
		DMERR("Couldn't create pending pool.");
		r = -ENOMEM;
		goto bad5;
	}

	return 0;

 bad5:
	kmem_cache_destroy(pending_cachep);
 bad4:
	kmem_cache_destroy(exception_cachep);
 bad3:
	exit_origin_hash();
 bad2:
	dm_unregister_target(&origin_target);
 bad1:
	dm_unregister_target(&snapshot_target);
	return r;
}

void dm_snapshot_exit(void)
{
	int r;

	r = dm_unregister_target(&snapshot_target);
	if (r)
		DMERR("snapshot unregister failed %d", r);

	r = dm_unregister_target(&origin_target);
	if (r)
		DMERR("origin unregister failed %d", r);

	exit_origin_hash();
	mempool_destroy(pending_pool);
	kmem_cache_destroy(pending_cachep);
	kmem_cache_destroy(exception_cachep);
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
