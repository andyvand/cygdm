/*
 * dm-snapshot.c
 *
 * Copyright (C) 2001-2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm-snapshot.h"
#include "kcopyd.h"
#include <linux/mm.h>
#include <linux/pagemap.h>

#define SECTOR_SIZE 512
#define SECTOR_SHIFT 9

/*-----------------------------------------------------------------
 * Persistent snapshots, by persistent we mean that the snapshot
 * will survive a reboot.
 *---------------------------------------------------------------*/

/*
 * We need to store a record of which parts of the origin have
 * been copied to the snapshot device.  The snapshot code
 * requires that we copy exception chunks to chunk aligned areas
 * of the COW store.  It makes sense therefore, to store the
 * metadata in chunk size blocks.
 *
 * There is no backward or forward compatibility implemented,
 * snapshots with different disk versions than the kernel will
 * not be usable.  It is expected that "lvcreate" will blank out
 * the start of a fresh COW device before calling the snapshot
 * constructor.
 *
 * The first chunk of the COW device just contains the header.
 * After this there is a chunk filled with exception metadata,
 * followed by as many exception chunks as can fit in the
 * metadata areas.
 *
 * All on disk structures are in little-endian format.  The end
 * of the exceptions info is indicated by an exception with a
 * new_chunk of 0, which is invalid since it would point to the
 * header chunk.
 */

/*
 * Magic for persistent snapshots: "SnAp" - Feeble isn't it.
 */
#define SNAP_MAGIC 0x70416e53

/*
 * The on-disk version of the metadata.
 */
#define SNAPSHOT_DISK_VERSION 1

struct disk_header {
	uint32_t magic;

	/*
	 * Is this snapshot valid.  There is no way of recovering
	 * an invalid snapshot.
	 */
	int valid;

	/*
	 * Simple, incrementing version. no backward
	 * compatibility.
	 */
	uint32_t version;

	/* In sectors */
	uint32_t chunk_size;
};

struct disk_exception {
	uint64_t old_chunk;
	uint64_t new_chunk;
};

struct commit_callback {
	void (*callback)(void *, int success);
	void *context;
};

/*
 * The top level structure for a persistent exception store.
 */
struct pstore {
	struct dm_snapshot *snap;	/* up pointer to my snapshot */
	int version;
	int valid;
	uint32_t chunk_size;
	uint32_t exceptions_per_area;

	/*
	 * Now that we have an asynchronous kcopyd there is no
	 * need for large chunk sizes, so it wont hurt to have a
	 * whole chunks worth of metadata in memory at once.
	 */
	void *area;
	struct kiobuf *iobuf;

	/*
	 * Used to keep track of which metadata area the data in
	 * 'chunk' refers to.
	 */
	uint32_t current_area;

	/*
	 * The next free chunk for an exception.
	 */
	uint32_t next_free;

	/*
	 * The index of next free exception in the current
	 * metadata area.
	 */
	uint32_t current_committed;

	atomic_t pending_count;
	uint32_t callback_count;
	struct commit_callback *callbacks;
};

/*
 * For performance reasons we want to defer writing a committed
 * exceptions metadata to disk so that we can amortise away this
 * exensive operation.
 *
 * For the initial version of this code we will remain with
 * synchronous io.  There are some deadlock issues with async
 * that I haven't yet worked out.
 */
static int do_io(int rw, struct kcopyd_region *where, struct kiobuf *iobuf)
{
	int i, sectors_per_block, nr_blocks, start;
	int blocksize = get_hardsect_size(where->dev);
	int status;

	sectors_per_block = blocksize / SECTOR_SIZE;

	nr_blocks = where->count / sectors_per_block;
	start = where->sector / sectors_per_block;

	for (i = 0; i < nr_blocks; i++)
		iobuf->blocks[i] = start++;

	iobuf->length = where->count << 9;
	iobuf->locked = 1;

	status = brw_kiovec(rw, 1, &iobuf, where->dev, iobuf->blocks,
			    blocksize);
	if (status != (where->count << 9))
		return -EIO;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION ( 2, 4, 19)
/*
 * FIXME: Remove once 2.4.19 has been released.
 */
struct page *vmalloc_to_page(void *vmalloc_addr)
{
	unsigned long addr = (unsigned long) vmalloc_addr;
	struct page *page = NULL;
	pmd_t *pmd;
	pte_t *pte;
	pgd_t *pgd;

	pgd = pgd_offset_k(addr);
	if (!pgd_none(*pgd)) {
		pmd = pmd_offset(pgd, addr);
		if (!pmd_none(*pmd)) {
			pte = pte_offset(pmd, addr);
			if (pte_present(*pte)) {
				page = pte_page(*pte);
			}
		}
	}
	return page;
}
#endif

static int allocate_iobuf(struct pstore *ps)
{
	size_t i, r = -ENOMEM, len, nr_pages;
	struct page *page;

	len = ps->chunk_size << SECTOR_SHIFT;

	/*
	 * Allocate the chunk_size block of memory that will hold
	 * a single metadata area.
	 */
	ps->area = vmalloc(len);
	if (!ps->area)
		return r;

	if (alloc_kiovec(1, &ps->iobuf))
		goto bad;

	nr_pages = ps->chunk_size / (PAGE_SIZE / SECTOR_SIZE);
	r = expand_kiobuf(ps->iobuf, nr_pages);
	if (r)
		goto bad;

	/*
	 * We lock the pages for ps->area into memory since they'll be
	 * doing a lot of io.
	 */
	for (i = 0; i < nr_pages; i++) {
		page = vmalloc_to_page(ps->area + (i * PAGE_SIZE));
		LockPage(page);
		ps->iobuf->maplist[i] = page;
		ps->iobuf->nr_pages++;
	}

	ps->iobuf->nr_pages = nr_pages;
	ps->iobuf->offset = 0;

	return 0;

      bad:
	if (ps->iobuf)
		free_kiovec(1, &ps->iobuf);

	if (ps->area)
		vfree(ps->area);
	ps->iobuf = NULL;
	return r;
}

static void free_iobuf(struct pstore *ps)
{
	int i;

	for (i = 0; i < ps->iobuf->nr_pages; i++)
		UnlockPage(ps->iobuf->maplist[i]);
	ps->iobuf->locked = 0;

	free_kiovec(1, &ps->iobuf);
	vfree(ps->area);
}

/*
 * Read or write a chunk aligned and sized block of data from a device.
 */
static int chunk_io(struct pstore *ps, uint32_t chunk, int rw)
{
	int r;
	struct kcopyd_region where;

	where.dev = ps->snap->cow->dev;
	where.sector = ps->chunk_size * chunk;
	where.count = ps->chunk_size;

	r = do_io(rw, &where, ps->iobuf);
	if (r)
		return r;

	return 0;
}

/*
 * Read or write a metadata area.  Remembering to skip the first
 * chunk which holds the header.
 */
static int area_io(struct pstore *ps, uint32_t area, int rw)
{
	int r;
	uint32_t chunk;

	/* convert a metadata area index to a chunk index */
	chunk = 1 + ((ps->exceptions_per_area + 1) * area);

	r = chunk_io(ps, chunk, rw);
	if (r)
		return r;

	ps->current_area = area;
	return 0;
}

static int zero_area(struct pstore *ps, uint32_t area)
{
	memset(ps->area, 0, ps->chunk_size << SECTOR_SHIFT);
	return area_io(ps, area, WRITE);
}

static int read_header(struct pstore *ps, int *new_snapshot)
{
	int r;
	struct disk_header *dh;

	r = chunk_io(ps, 0, READ);
	if (r)
		return r;

	dh = (struct disk_header *) ps->area;

	if (dh->magic == 0) {
		*new_snapshot = 1;

	} else if (dh->magic == SNAP_MAGIC) {
		*new_snapshot = 0;
		ps->valid = dh->valid;
		ps->version = dh->version;
		ps->chunk_size = dh->chunk_size;

	} else {
		DMWARN("Invalid/corrupt snapshot");
		r = -ENXIO;
	}

	return r;
}

static int write_header(struct pstore *ps)
{
	struct disk_header *dh;

	memset(ps->area, 0, ps->chunk_size << SECTOR_SHIFT);

	dh = (struct disk_header *) ps->area;
	dh->magic = SNAP_MAGIC;
	dh->valid = ps->valid;
	dh->version = ps->version;
	dh->chunk_size = ps->chunk_size;

	return chunk_io(ps, 0, WRITE);
}

/*
 * Access functions for the disk exceptions, these do the endian conversions.
 */
static struct disk_exception *get_exception(struct pstore *ps, uint32_t index)
{
	if (index >= ps->exceptions_per_area)
		return NULL;

	return ((struct disk_exception *) ps->area) + index;
}

static int read_exception(struct pstore *ps,
			  uint32_t index, struct disk_exception *result)
{
	struct disk_exception *e;

	e = get_exception(ps, index);
	if (!e)
		return -EINVAL;

	/* copy it */
	result->old_chunk = le64_to_cpu(e->old_chunk);
	result->new_chunk = le64_to_cpu(e->new_chunk);

	return 0;
}

static int write_exception(struct pstore *ps,
			   uint32_t index, struct disk_exception *de)
{
	struct disk_exception *e;

	e = get_exception(ps, index);
	if (!e)
		return -EINVAL;

	/* copy it */
	e->old_chunk = cpu_to_le64(de->old_chunk);
	e->new_chunk = cpu_to_le64(de->new_chunk);

	return 0;
}

/*
 * Registers the exceptions that are present in the current area.
 * 'full' is filled in to indicate if the area has been
 * filled.
 */
static int insert_exceptions(struct pstore *ps, int *full)
{
	int i, r;
	struct disk_exception de;

	/* presume the area is full */
	*full = 1;

	for (i = 0; i < ps->exceptions_per_area; i++) {
		r = read_exception(ps, i, &de);

		if (r)
			return r;

		/*
		 * If the new_chunk is pointing at the start of
		 * the COW device, where the first metadata area
		 * is we know that we've hit the end of the
		 * exceptions.  Therefore the area is not full.
		 */
		if (de.new_chunk == 0LL) {
			ps->current_committed = i;
			*full = 0;
			break;
		}

		/*
		 * Keep track of the start of the free chunks.
		 */
		if (ps->next_free <= de.new_chunk)
			ps->next_free = de.new_chunk + 1;

		/*
		 * Otherwise we add the exception to the snapshot.
		 */
		r = dm_add_exception(ps->snap, de.old_chunk, de.new_chunk);
		if (r)
			return r;
	}

	return 0;
}

static int read_exceptions(struct pstore *ps)
{
	uint32_t area;
	int r, full = 1;

	/*
	 * Keeping reading chunks and inserting exceptions until
	 * we find a partially full area.
	 */
	for (area = 0; full; area++) {
		r = area_io(ps, area, READ);
		if (r)
			return r;

		r = insert_exceptions(ps, &full);
		if (r)
			return r;

		area++;
	}

	return 0;
}

static inline struct pstore *get_info(struct exception_store *store)
{
	return (struct pstore *) store->context;
}

static int persistent_percentfull(struct exception_store *store)
{
	struct pstore *ps = get_info(store);
	return (ps->next_free * store->snap->chunk_size * 100) /
	    get_dev_size(store->snap->cow->dev);
}

static void persistent_destroy(struct exception_store *store)
{
	struct pstore *ps = get_info(store);

	vfree(ps->callbacks);
	free_iobuf(ps);
	kfree(ps);
}

static int persistent_prepare(struct exception_store *store,
			      struct exception *e)
{
	struct pstore *ps = get_info(store);
	uint32_t stride;
	offset_t size = get_dev_size(store->snap->cow->dev);

	/* Is there enough room ? */
	if (size <= (ps->next_free * store->snap->chunk_size))
		return -ENOSPC;

	e->new_chunk = ps->next_free;

	/*
	 * Move onto the next free pending, making sure to take
	 * into account the location of the metadata chunks.
	 */
	stride = (ps->exceptions_per_area + 1);
	if (!(++ps->next_free % stride))
		ps->next_free++;

	atomic_inc(&ps->pending_count);
	return 0;
}

static void persistent_commit(struct exception_store *store,
			      struct exception *e,
			      void (*callback) (void *, int success),
			      void *callback_context)
{
	int r, i;
	struct pstore *ps = get_info(store);
	struct disk_exception de;
	struct commit_callback *cb;

	de.old_chunk = e->old_chunk;
	de.new_chunk = e->new_chunk;
	write_exception(ps, ps->current_committed++, &de);

	/*
	 * Add the callback to the back of the array.  This code
	 * is the only place where the callback array is
	 * manipulated, and we know that it will never be called
	 * multiple times concurrently.
	 */
	cb = ps->callbacks + ps->callback_count++;
	cb->callback = callback;
	cb->context = callback_context;

	/*
	 * If there are no more exceptions in flight, or we have
	 * filled this metadata area we commit the exceptions to
	 * disk.
	 */
	if (atomic_dec_and_test(&ps->pending_count) ||
	    (ps->current_committed == ps->exceptions_per_area)) {
		r = area_io(ps, ps->current_area, WRITE);
		if (r)
			ps->valid = 0;

		for (i = 0; i < ps->callback_count; i++) {
			cb = ps->callbacks + i;
			cb->callback(cb->context, r == 0 ? 1 : 0);
		}

		ps->callback_count = 0;
	}

	/*
	 * Have we completely filled the current area ?
	 */
	if (ps->current_committed == ps->exceptions_per_area) {
		ps->current_committed = 0;
		r = zero_area(ps, ps->current_area + 1);
		if (r)
			ps->valid = 0;
	}
}

static void persistent_drop(struct exception_store *store)
{
	struct pstore *ps = get_info(store);

	ps->valid = 0;
	if (write_header(ps))
		DMWARN("write header failed");
}

int dm_create_persistent(struct exception_store *store, uint32_t chunk_size)
{
	int r, new_snapshot;
	struct pstore *ps;

	/* allocate the pstore */
	ps = kmalloc(sizeof(*ps), GFP_KERNEL);
	if (!ps)
		return -ENOMEM;

	ps->snap = store->snap;
	ps->valid = 1;
	ps->version = SNAPSHOT_DISK_VERSION;
	ps->chunk_size = chunk_size;
	ps->exceptions_per_area = (chunk_size << SECTOR_SHIFT) /
	    sizeof(struct disk_exception);
	ps->next_free = 2;	/* skipping the header and first area */
	ps->current_committed = 0;

	r = allocate_iobuf(ps);
	if (r)
		goto bad;

	/*
	 * Allocate space for all the callbacks.
	 */
	ps->callback_count = 0;
	atomic_set(&ps->pending_count, 0);
	ps->callbacks = vcalloc(ps->exceptions_per_area,
				sizeof(*ps->callbacks));

	if (!ps->callbacks)
		goto bad;

	/*
	 * Read the snapshot header.
	 */
	r = read_header(ps, &new_snapshot);
	if (r)
		goto bad;

	/*
	 * Do we need to setup a new snapshot ?
	 */
	if (new_snapshot) {
		r = write_header(ps);
		if (r) {
			DMWARN("write_header failed");
			goto bad;
		}

		r = zero_area(ps, 0);
		if (r) {
			DMWARN("zero_area(0) failed");
			goto bad;
		}

	} else {
		/*
		 * Sanity checks.
		 */
		if (ps->chunk_size != chunk_size) {
			DMWARN("chunk size for existing snapshot different "
			       "from that requested");
			r = -EINVAL;
			goto bad;
		}

		if (ps->version != SNAPSHOT_DISK_VERSION) {
			DMWARN("unable to handle snapshot disk version %d",
			       ps->version);
			r = -EINVAL;
			goto bad;
		}

		/*
		 * Read the metadata.
		 */
		r = read_exceptions(ps);
		if (r)
			goto bad;
	}

	store->destroy = persistent_destroy;
	store->prepare_exception = persistent_prepare;
	store->commit_exception = persistent_commit;
	store->drop_snapshot = persistent_drop;
	store->percent_full = persistent_percentfull;
	store->context = ps;

	return r;

      bad:
	if (ps) {
		if (ps->callbacks)
			vfree(ps->callbacks);

		if (ps->iobuf)
			free_iobuf(ps);

		kfree(ps);
	}
	return r;
}

/*-----------------------------------------------------------------
 * Implementation of the store for non-persistent snapshots.
 *---------------------------------------------------------------*/
struct transient_c {
	offset_t next_free;
};

void transient_destroy(struct exception_store *store)
{
	kfree(store->context);
}

int transient_prepare(struct exception_store *store, struct exception *e)
{
	struct transient_c *tc = (struct transient_c *) store->context;
	offset_t size = get_dev_size(store->snap->cow->dev);

	if (size < (tc->next_free + store->snap->chunk_size))
		return -1;

	e->new_chunk = sector_to_chunk(store->snap, tc->next_free);
	tc->next_free += store->snap->chunk_size;

	return 0;
}

void transient_commit(struct exception_store *store,
		      struct exception *e,
		      void (*callback) (void *, int success),
		      void *callback_context)
{
	/* Just succeed */
	callback(callback_context, 1);
}

static int transient_percentfull(struct exception_store *store)
{
	struct transient_c *tc = (struct transient_c *) store->context;
	return (tc->next_free * 100) / get_dev_size(store->snap->cow->dev);
}

int dm_create_transient(struct exception_store *store,
			struct dm_snapshot *s, int blocksize, void **error)
{
	struct transient_c *tc;

	memset(store, 0, sizeof(*store));
	store->destroy = transient_destroy;
	store->prepare_exception = transient_prepare;
	store->commit_exception = transient_commit;
	store->percent_full = transient_percentfull;
	store->snap = s;

	tc = kmalloc(sizeof(struct transient_c), GFP_KERNEL);
	if (!tc)
		return -ENOMEM;

	tc->next_free = 0;
	store->context = tc;

	return 0;
}
