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
 * The very first metadata block, which is also the first chunk
 * on the COW device, will include a header struct followed by
 * exception info.  All other metadata chunks will solely consist
 * of exception info.  All on disk structures are in
 * little-endian format.  The end of the exceptions info is
 * indicated by an exception with a new_chunk of 0.
 */

/*
 * Magic for persistent snapshots: "SnAp" - Feeble isn't it.
 */
#define SNAP_MAGIC 0x70416e53

/*
 * The on-disk version of the metadata.
 */
#define SNAPSHOT_DISK_VERSION 1

#if 0
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
#endif

struct disk_exception {
	uint64_t old_chunk;
	uint64_t new_chunk;
};

/*
 * The top level structure for a persistent exception store.
 */
struct pstore {
	struct dm_snapshot *snap;	/* up pointer to my snapshot */
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

	status = brw_kiovec(rw, 1, &iobuf, where->dev, iobuf->blocks,
			    blocksize);
	if (status != (where->count << 9))
		return -EIO;

	return 0;
}

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

static int allocate_iobuf(struct pstore *ps)
{
	size_t i, r, len, nr_pages;
	struct page *page;

	len = ps->chunk_size * SECTOR_SIZE;

	/*
	 * Allocate the chunk_size block of memory that will hold
	 * a single metadata area.
	 */
	ps->area = vmalloc(len);
	if (!ps->area)
		return -ENOMEM;

	if (alloc_kiovec(1, &ps->iobuf)) {
		vfree(ps->area);
		return -ENOMEM;
	}

	nr_pages = ps->chunk_size / (PAGE_SIZE / SECTOR_SIZE);
	r = expand_kiobuf(ps->iobuf, nr_pages);
	if (r) {
		vfree(ps->area);
		return -ENOMEM;
	}

	/*
	 * We lock the pages for ps->area into memory since they'll be
	 * doing a lot of io.
	 *
	 * FIXME: Check that there's no race, ie. the pages can't
	 * be swapped out before we lock them, we may have to
	 * allocate them as seperate pages after all :(
	 */
	for (i = 0; i < len; i += PAGE_SIZE) {
		page = vmalloc_to_page(ps->area + i);
		LockPage(page);
		ps->iobuf->maplist[i] = page;
		ps->iobuf->nr_pages++;
	}

	ps->iobuf->offset = 0;
	return 0;
}

static void free_iobuf(struct pstore *ps)
{
	int i;

	for (i = 0; i < ps->iobuf->nr_pages; i++)
		UnlockPage(ps->iobuf->maplist[i]);

	free_kiovec(1, &ps->iobuf);
	vfree(ps->area);
}

/*
 * Read or write a metadata area.
 */
static int area_io(struct pstore *ps, uint32_t area, int rw)
{
	int r;
	struct kcopyd_region where;

	where.dev = ps->snap->cow->dev;
	where.sector = ((ps->exceptions_per_area + 1) * ps->chunk_size) * area;
	where.count = ps->chunk_size;

	r = do_io(rw, &where, ps->area);
	if (r)
		return r;

	ps->current_area = area;
	return 0;
}

static int zero_area(struct pstore *ps, uint32_t area)
{
	memset(ps, 0, ps->chunk_size);
	return area_io(ps, area, WRITE);
}

/*
 * Access functions for the disk exceptions, these do the endian conversions.
 */
static struct disk_exception *get_exception(struct pstore *ps, uint32_t index)
{
	if (index > ps->exceptions_per_area)
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
	memcpy(result, e, sizeof(&result));

	result->old_chunk = le64_to_cpu(result->old_chunk);
	result->new_chunk = le64_to_cpu(result->new_chunk);

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
	e->old_chunk = cpu_to_le64(e->old_chunk);
	e->new_chunk = cpu_to_le64(e->new_chunk);

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
		 * exceptions.  Therefor the area is not full.
		 */
		if (de.new_chunk) {
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
	int r, full = 0;

	/*
	 * Keeping reading chunks and inserting exceptions until
	 * we find a partially full area.
	 */
	for (area = 0; !full; area++) {
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

static void persistent_destroy(struct exception_store *store)
{
	struct pstore *ps = get_info(store);

	free_iobuf(ps);
	vfree(ps->area);
	kfree(ps);
}

static int persistent_prepare(struct exception_store *store,
			      struct exception *e)
{
	struct pstore *ps = get_info(store);
	uint32_t stride;

	e->new_chunk = ps->next_free;

	/*
	 * Move onto the next free pending, making sure to take
	 * into account the location of the metadata chunks.
	 */
	stride = (ps->exceptions_per_area + 1);
	if (!(++ps->next_free % stride))
		ps->next_free++;

	return 0;
}

static void persistent_commit(struct exception_store *store,
			      struct exception *e,
			      void (*callback) (void *, int success),
			      void *callback_context)
{
	int r;
	struct pstore *ps = get_info(store);
	struct disk_exception de;

	de.old_chunk = e->old_chunk;
	de.new_chunk = e->new_chunk;
	write_exception(ps, ps->current_committed, &de);

	/*
	 * Write the whole area to the disk for now, later we'll
	 * try and defer the write.
	 */
	r = area_io(ps, ps->current_area, WRITE);
	if (r)
		goto bad;

	/*
	 * Notify the snapshot that the commit has actually
	 * happened.
	 */
	callback(callback_context, 1);

	/*
	 * Have we completely filled the current area ?
	 */
	if (++ps->current_committed > ps->exceptions_per_area) {
		ps->current_committed = 0;
		r = zero_area(ps, ps->current_area + 1);
		if (r)
			goto bad;
	}

	return;

      bad:
	ps->valid = 0;
	callback(callback_context, 0);
}

static void persistent_drop(struct exception_store *store)
{
	struct pstore *ps = get_info(store);

	/*
	 * FIXME: This function is pointless until we have the
	 * header.
	 */
	ps->valid = 0;
}

int persistent_init(struct exception_store *store, uint32_t chunk_size)
{
	int r;
	struct pstore *ps;

	/* allocate the pstore */
	ps = kmalloc(sizeof(*ps), GFP_KERNEL);
	if (!ps)
		return -ENOMEM;

	r = allocate_iobuf(ps);
	if (r)
		return r;

	ps->snap = store->snap;
	ps->valid = 1;
	ps->chunk_size = chunk_size;
	ps->exceptions_per_area = (chunk_size << SECTOR_SHIFT) /
	    sizeof(struct disk_exception);
	ps->next_free = 1;
	ps->current_committed = 0;

	/*
	 * Read the metadata.
	 */
	r = read_exceptions(ps);
	if (r) {
		free_iobuf(ps);
		kfree(ps);
	}

	store->destroy = persistent_destroy;
	store->prepare_exception = persistent_prepare;
	store->commit_exception = persistent_commit;
	store->drop_snapshot = persistent_drop;
	store->context = ps;

	return r;
}

/*-----------------------------------------------------------------
 * Implementation of the store for non-persistent snapshots.
 *---------------------------------------------------------------*/
struct transient_c {
	offset_t next_free;
};

void destroy_transient(struct exception_store *store)
{
	kfree(store->context);
}

int prepare_transient(struct exception_store *store, struct exception *e)
{
	struct transient_c *tc = (struct transient_c *) store->context;
	offset_t size = get_dev_size(store->snap->cow->dev);

	if (size < (tc->next_free + store->snap->chunk_size))
		return -1;

	e->new_chunk = sector_to_chunk(store->snap, tc->next_free);
	tc->next_free += store->snap->chunk_size;

	return 0;
}

void commit_transient(struct exception_store *store,
		      struct exception *e,
		      void (*callback) (void *, int success),
		      void *callback_context)
{
	/* Just succeed */
	callback(callback_context, 1);
}

int percentfull_transient(struct exception_store *store)
{
	struct transient_c *tc = (struct transient_c *) store->context;
	return (tc->next_free * 100) / get_dev_size(store->snap->cow->dev);
}

int dm_create_transient(struct exception_store *store,
			struct dm_snapshot *s, int blocksize, void **error)
{
	struct transient_c *tc;

	memset(store, 0, sizeof(*store));
	store->destroy = destroy_transient;
	store->prepare_exception = prepare_transient;
	store->commit_exception = commit_transient;
	store->percent_full = percentfull_transient;
	store->snap = s;

	tc = kmalloc(sizeof(struct transient_c), GFP_KERNEL);
	if (!tc)
		return -ENOMEM;

	tc->next_free = 0;
	store->context = tc;

	return 0;
}
