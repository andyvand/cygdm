/*
 * dm-snapshot.c
 *
 * Copyright (C) 2001-2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm-snapshot.h"

#if 0
/*
 * Magic for persistent snapshots: "SnAp" - Feeble isn't it.
 */
#define SNAP_MAGIC 0x70416e53

/*
 * The on-disk version of the metadata. Only applicable to
 * persistent snapshots.
 * There is no backward or forward compatibility implemented, snapshots
 * with different disk versions than the kernel will not be usable. It is
 * expected that "lvcreate" will blank out the start of the COW device
 * before calling the snapshot constructor.
 */
#define SNAPSHOT_DISK_VERSION 1

/*
 * Metadata format: (please keep this up-to-date!)
 * Persistent snapshots have a 1 block header (see below for structure) at
 * the very start of the device. The COW metadata starts at
 * .start_of_exceptions.
 *
 * COW metadata is stored in blocks that are "extent-size" sectors long as
 * an array of disk_exception structures in Little-Endian format.
 * The last entry in this array has rsector_new set to 0 (this cannot be a
 * legal redirection as the header is here) and if rsector_org has a value
 * it is the sector number of the next COW metadata sector on the disk. if
 * rsector_org is also zero then this is the end of the COW metadata.
 *
 * The metadata is written in hardblocksize lumps rather than in units of
 * extents for efficiency so don't expect a whole extent to be zeroed out
 * at any time.
 *
 * Non-persistent snapshots simple have redirected blocks stored
 * (in chunk_size sectors) from hard block 1 to avoid inadvertantly
 * creating a bad header.
 */

/*
 * Internal snapshot structure
 */
struct persistent_info {
	/* Size of extents used for COW blocks */
        long extent_size;

	/* Number of the next free sector for COW/data */
	unsigned long next_free_sector;

	/* Where the metadata starts */
	unsigned long start_of_exceptions;

	/* Where we are currently writing the metadata */
	unsigned long current_metadata_sector;

	/* Index into disk_cow array */
	int current_metadata_entry;

	/* Index into mythical extent array */
	int current_metadata_number;

	/* Number of metadata entries in the disk_cow array */
	int highest_metadata_entry;

	/* Number of metadata entries per hard disk block */
	int md_entries_per_block;

	/* kiobuf for doing I/O to header & metadata */
	struct kiobuf *cow_iobuf;

	 /*
	  * Disk extent with COW data in it. as an array of
	  * exception tables. The first one points to the next
	  * block of metadata or 0 if this is the last
	  */
	struct disk_exception *disk_cow;
};

/*
 * An array of these is held in each disk block. LE format
 */
struct disk_exception {
	uint64_t rsector_org;
	uint64_t rsector_new;
};

/*
 * Structure of a (persistent) snapshot header on disk. in LE format
 */
struct snap_disk_header {
	uint32_t magic;

	/* Simple, incrementing version. no backward compatibility */
	uint32_t version;

	/* In 512 byte sectors */
	uint32_t chunk_size;

	/* In 512 byte sectors */
	uint32_t extent_size;
	uint64_t start_of_exceptions;
	uint32_t full;
};

/*
 * READ or WRITE some blocks to/from a device
 */
static int do_io(int rw, struct kiobuf *iobuf, kdev_t dev,
		 unsigned long start, int nr_sectors)
{
	int i, sectors_per_block, nr_blocks;
	int blocksize = get_hardsect_size(dev);
	int status;

	sectors_per_block = blocksize / SECTOR_SIZE;

	nr_blocks = nr_sectors / sectors_per_block;
	start /= sectors_per_block;

	for (i = 0; i < nr_blocks; i++)
		iobuf->blocks[i] = start++;

	iobuf->length = nr_sectors << 9;

	status = brw_kiovec(rw, 1, &iobuf, dev, iobuf->blocks, blocksize);
	return (status != (nr_sectors << 9));
}

/*
 * Write the latest COW metadata block.
 */
static int write_metadata(struct snapshot_c *s, struct persistent_info *pi)
{
	kdev_t dev = s->cow_dev->dev;
	int blocksize = get_hardsect_size(dev);
	int writesize = blocksize/SECTOR_SIZE;

	if (do_io(WRITE, pi->cow_iobuf, dev,
		  pi->current_metadata_sector, writesize) != 0) {
		DMERR("Error writing COW block");
		return -1;
	}

	return 0;
}

/*
 * Allocate a kiobuf. This is the only code nicked from the old
 * snapshot driver and I've changed it anyway.
 */
static int alloc_iobuf_pages(struct kiobuf *iobuf, int nr_sectors)
{
	int nr_pages, err, i;

	if (nr_sectors > KIO_MAX_SECTORS)
		return -1;

	nr_pages = nr_sectors / (PAGE_SIZE/SECTOR_SIZE);
	err = expand_kiobuf(iobuf, nr_pages);
	if (err) goto out;

	err = -ENOMEM;
	iobuf->locked = 1;
	iobuf->nr_pages = 0;
	for (i = 0; i < nr_pages; i++) {
		struct page * page;

		page = alloc_page(GFP_KERNEL);
		if (!page) goto out;

		iobuf->maplist[i] = page;
		LockPage(page);
		iobuf->nr_pages++;
	}
	iobuf->offset = 0;

	err = 0;

out:
	return err;
}

/*
 * Read on-disk COW metadata and populate the hash table.
 */
static int read_metadata(struct snapshot_c *lc, struct persistent_info *pi)
{
	int status;
	int i;
	int entry = 0;
	int map_page = 0;
	int nr_sectors = pi->extent_size;
	kdev_t dev = lc->cow_dev->dev;
	int blocksize = get_hardsect_size(dev);
	unsigned long cur_sector = pi->start_of_exceptions;
	unsigned long last_sector;
	unsigned long first_free_sector = 0;
	int entries_per_page = PAGE_SIZE / sizeof(struct disk_exception);
	struct disk_exception *cow_block;
	struct kiobuf *read_iobuf;
	int err = 0;
	int devsize = get_dev_size(dev);

	/*
	 * Allocate our own iovec for this operation 'cos the
	 * others are way too small.
	 */
	if (alloc_kiovec(1, &read_iobuf)) {
		DMERR("Error allocating iobuf for %s",
		      kdevname(dev));
		return -1;
	}

	if (alloc_iobuf_pages(read_iobuf, pi->extent_size)) {
		DMERR("Error allocating iobuf space for %s",
		      kdevname(dev));
		free_kiovec(1, &read_iobuf);
		return -1;
	}
	cow_block = page_address(read_iobuf->maplist[0]);

	do {
		/* Make sure the chain does not go off the end of
		 * the device, or backwards */
		if (cur_sector > devsize || cur_sector < first_free_sector) {
			DMERR("COW table chain pointers are inconsistent, "
			      "can't activate snapshot");
			err = -1;
			goto ret_free;
		}

		first_free_sector = max(first_free_sector,
					cur_sector + pi->extent_size);
		status = do_io(READ, read_iobuf, dev,
			       cur_sector, nr_sectors);
		if (status == 0) {

			map_page = 0;
			entry = 0;

			cow_block = page_address(read_iobuf->maplist[0]);

			/* Now populate the hash table from this data */
			for (i = 0; i <= pi->highest_metadata_entry &&
				     cow_block[entry].rsector_new != 0; i++) {

				struct exception *ex;

				ex = add_exception(lc,
						   le64_to_cpu(cow_block[entry].rsector_org),
						   le64_to_cpu(cow_block[entry].rsector_new));

				first_free_sector = max(first_free_sector,
							(unsigned long)(le64_to_cpu(cow_block[entry].rsector_new) +
									lc->chunk_size));

				/* Do we need to move onto the next page? */
				if (++entry >= entries_per_page) {
					entry = 0;
					cow_block = page_address(read_iobuf->maplist[++map_page]);
				}
			}
		}
		else {
			DMERR("Error reading COW metadata for %s",
			      kdevname(dev));
			err = -1;
			goto ret_free;
		}
		last_sector = cur_sector;
		cur_sector = le64_to_cpu(cow_block[entry].rsector_org);

	} while (cur_sector != 0);

	lc->persistent = 1;
	pi->current_metadata_sector = last_sector +
		                      map_page*PAGE_SIZE/SECTOR_SIZE +
                                      entry/(SECTOR_SIZE/sizeof(struct disk_exception));
	pi->current_metadata_entry  = entry;
	pi->current_metadata_number = i;
	pi->next_free_sector = first_free_sector;

	/* Copy last block into cow_iobuf */
	memcpy(pi->disk_cow, (char *)((long)&cow_block[entry] - ((long)&cow_block[entry] & (blocksize-1))), blocksize);

 ret_free:
	unmap_kiobuf(read_iobuf);
	free_kiovec(1, &read_iobuf);

	return err;
}

/*
 * Read the snapshot volume header, returns 0 only if it read OK
 * and it was valid. returns 1 if no header was found, -1 on
 * error.  All fields are checked against the snapshot structure
 * itself to make sure we don't corrupt the data.
 */
static int read_header(struct snapshot_c *lc, struct persistent_info *pi)
{
	int status;
	struct snap_disk_header *header;
	kdev_t dev = lc->cow_dev->dev;
	int blocksize = get_hardsect_size(dev);
	unsigned long devsize;

	/* Get it */
	status = do_io(READ, pi->cow_iobuf, dev, 0L, blocksize/SECTOR_SIZE);
	if (status != 0) {
		DMERR("Snapshot dev %s error reading header",
		      kdevname(dev));
		return -1;
	}

	header = (struct snap_disk_header *) page_address(pi->cow_iobuf->maplist[0]);

	/*
	 * Check the magic. It's OK if this fails, we just create a new snapshot header
	 * and start from scratch
	 */
	if (le32_to_cpu(header->magic) != SNAP_MAGIC) {
		return 1;
	}

	/* Check the version matches */
	if (le32_to_cpu(header->version) != SNAPSHOT_DISK_VERSION) {
		DMWARN("Snapshot dev %s version mismatch. Stored: %d, driver: %d",
		       kdevname(dev), le32_to_cpu(header->version), SNAPSHOT_DISK_VERSION);
		return -1;
	}

	/* Check the chunk sizes match */
	if (le32_to_cpu(header->chunk_size) != lc->chunk_size) {
		DMWARN("Snapshot dev %s chunk size mismatch. Stored: %d, requested: %d",
		       kdevname(dev), le32_to_cpu(header->chunk_size), lc->chunk_size);
		return -1;
	}

	/* Check the extent sizes match */
	if (le32_to_cpu(header->extent_size) != pi->extent_size) {
		DMWARN("Snapshot dev %s extent size mismatch. Stored: %d, requested: %ld",
		       kdevname(dev), le32_to_cpu(header->extent_size), pi->extent_size);
		return -1;
	}

	/* Get the rest of the data */
	pi->start_of_exceptions = le64_to_cpu(header->start_of_exceptions);
	if (header->full) {
		DMWARN("Snapshot dev %s is full. It cannot be used", kdevname(dev));
		lc->full = 1;
		return -1;
	}

	/* Validate against the size of the volume */
	devsize = get_dev_size(dev);
	if (pi->start_of_exceptions > devsize) {
		DMWARN("Snapshot metadata error on %s. start exceptions > device size (%ld > %ld)",
		       kdevname(dev), pi->start_of_exceptions, devsize);
		return -1;
	}

	/* Read metadata into the hash table and update pointers */
	return read_metadata(lc, &lc->p_info);
}

/*
 * Write (or update) the header. The only time we should need to
 * do an update is when the snapshot becomes full.
 */
static int write_header(struct snapshot_c *lc, struct persistent_info *pi)
{
	struct snap_disk_header *header;
	struct kiobuf *head_iobuf;
	kdev_t dev = lc->cow_dev->dev;
	int blocksize = get_hardsect_size(dev);
	int status;

	/*
	 * Allocate our own iobuf for this so we don't corrupt
	 * any of the other writes that may be going on.
	 */
	if (alloc_kiovec(1, &head_iobuf)) {
		DMERR("Error allocating iobuf for header on %s", kdevname(dev));
		return -1;
	}

	if (alloc_iobuf_pages(head_iobuf, PAGE_SIZE/SECTOR_SIZE)) {
		DMERR("Error allocating iobuf space for header on %s", kdevname(dev));
		free_kiovec(1, &head_iobuf);
		return -1;
	}

	header = (struct snap_disk_header *) page_address(head_iobuf->maplist[0]);

	header->magic       = cpu_to_le32(SNAP_MAGIC);
	header->version     = cpu_to_le32(SNAPSHOT_DISK_VERSION);
	header->chunk_size  = cpu_to_le32(lc->chunk_size);
	header->extent_size = cpu_to_le32(pi->extent_size);
	header->full        = cpu_to_le32(lc->full);

	header->start_of_exceptions = cpu_to_le64(pi->start_of_exceptions);

	/* Must write at least a full block */
	status = do_io(WRITE, head_iobuf, dev, 0, blocksize/SECTOR_SIZE);

	unmap_kiobuf(head_iobuf);
	free_kiovec(1, &head_iobuf);
	return status;
}


static int init_persistent_snapshot(struct snapshot_c *lc, int blocksize,
				    unsigned long extent_size, void **context)
{
	struct persistent_info *pi = &lc->p_info;

	int status;
	int i;
	int cow_sectors;

	pi->extent_size = extent_size;
	pi->next_free_sector = blocksize / SECTOR_SIZE; /* Leave the first block alone */
	pi->disk_cow  = NULL;

	pi->highest_metadata_entry = (pi->extent_size*SECTOR_SIZE) / sizeof(struct disk_exception) - 1;
	pi->md_entries_per_block   = blocksize / sizeof(struct disk_exception);

	/* Allocate and set up iobuf for metadata I/O */
	*context = "Unable to allocate COW iovec";
	if (alloc_kiovec(1, &pi->cow_iobuf))
		return -1;

	/* Allocate space for the COW buffer. It should be at least PAGE_SIZE. */
	cow_sectors = blocksize/SECTOR_SIZE + PAGE_SIZE/SECTOR_SIZE;
	*context = "Unable to allocate COW I/O buffer space";
	if (alloc_iobuf_pages(pi->cow_iobuf, cow_sectors)) {
		free_kiovec(1, &pi->cow_iobuf);
		return -1;
	}

	for (i=0; i < pi->cow_iobuf->nr_pages; i++) {
		memset(page_address(pi->cow_iobuf->maplist[i]), 0, PAGE_SIZE);
	}

	pi->disk_cow = page_address(pi->cow_iobuf->maplist[0]);

	*context = "Error in disk header";
	/* Check for a header on disk and create a new one if not */
	if ( (status = read_header(lc, &lc->p_info)) == 1) {

		/* Write a new header */
		pi->start_of_exceptions = pi->next_free_sector;
		pi->next_free_sector += pi->extent_size;
		pi->current_metadata_sector = pi->start_of_exceptions;
		pi->current_metadata_entry  = 0;
		pi->current_metadata_number = 0;

		*context = "Unable to write snapshot header";
		if (write_header(lc, &lc->p_info) != 0) {
			DMERR("Error writing header to snapshot volume %s",
			      kdevname(lc->cow_dev->dev));
			goto free_ret;
		}

		/* Write a blank metadata block to the device */
		if (write_metadata(lc, &lc->p_info) != 0) {
			DMERR("Error writing initial COW table to snapshot volume %s",
			      kdevname(lc->cow_dev->dev));
			goto free_ret;
		}
	}

	/*
	 * There is a header but it doesn't match - fail so we
	 * don't destroy what might be useful data on disk.  If
	 * the user really wants to use this COW device for a
	 * snapshot then the first sector should be zeroed out
	 * first.
	 */
	if (status == -1)
		goto free_ret;

	return 0;

 free_ret:
	unmap_kiobuf(pi->cow_iobuf);
	free_kiovec(1, &pi->cow_iobuf);
	return -1;
}

static void exit_persistent_snapshot(struct persistent_info *pi)
{
	unmap_kiobuf(pi->cow_iobuf);
	free_kiovec(1, &pi->cow_iobuf);
}

/*
 * Finds a suitable destination for the exception.
 */
static int prepare_exception(struct snapshot_c *s,
			     struct inflight_exception *e)
{
	offset_t dev_size;

	/*
	 * Check for full snapshot. Doing the size calculation here means that
	 * the COW device can be resized without us being told
	 */
	dev_size = get_dev_size(s->cow_dev->dev);
	if (s->p_info.next_free_sector + s->chunk_size >= dev_size) {
		/* Snapshot is full, we can't use it */
		DMWARN("Snapshot %s is full (sec=%ld, size=%ld)",
		       kdevname(s->cow_dev->dev),
		       s->p_info.next_free_sector + s->chunk_size, dev_size);
		s->full = 1;

		/* Mark it full on the device */
		if (s->persistent)
			write_header(s, &s->p_info);

		return -1;

	} else {
		e->rsector_new = s->p_info.next_free_sector;
		s->p_info.next_free_sector += s->chunk_size;
	}

	return 0;
}

/*
 * Add a new exception entry to the on-disk metadata.
 */
static int commit_exception(struct snapshot_c *sc,
			    unsigned long org, unsigned long new)
{
	struct persistent_info *pi = &sc->p_info;

	int i = pi->current_metadata_entry++;
	unsigned long next_md_block = pi->current_metadata_sector;

	pi->current_metadata_number++;

	/* Update copy of disk COW */
	pi->disk_cow[i].rsector_org = cpu_to_le64(org);
	pi->disk_cow[i].rsector_new = cpu_to_le64(new);

	/* Have we filled this extent ? */
	if (pi->current_metadata_number >= pi->highest_metadata_entry) {
		/* Fill in pointer to next metadata extent */
		i++;
		pi->current_metadata_entry++;

		next_md_block = pi->next_free_sector;
		pi->next_free_sector += pi->extent_size;

		pi->disk_cow[i].rsector_org = cpu_to_le64(next_md_block);
		pi->disk_cow[i].rsector_new = 0;
	}

	/* Commit to disk */
	if (write_metadata(sc, &sc->p_info)) {
		sc->full = 1; /* Failed. don't try again */
		return -1;
	}

	/*
	 * Write a new (empty) metadata block if we are at the
	 * end of an existing block so that read_metadata finds a
	 * terminating zero entry.
	 */
	if (pi->current_metadata_entry == pi->md_entries_per_block) {
		memset(pi->disk_cow, 0, PAGE_SIZE);
		pi->current_metadata_sector = next_md_block;

		/*
		 * If this is also the end of an extent then go
		 * back to the start.
		 */
		if (pi->current_metadata_number >= pi->highest_metadata_entry) {
			pi->current_metadata_number = 0;

		} else {
			int blocksize = get_hardsect_size(sc->cow_dev->dev);
			pi->current_metadata_sector += blocksize/SECTOR_SIZE;
		}

		pi->current_metadata_entry = 0;
		if (write_metadata(sc, &sc->p_info) != 0) {
			sc->full = 1;
			return -1;
		}
	}
	return 0;
}

/*
 * Sets the full flag in the metadata.  A quick hack for now.
 */
static void invalidate_snapshot(struct snapshot_c *s)
{
	s->full = 1;
	if (s->persistent)
		write_header(s, &s->p_info);
}


#endif


struct exception_store * dm_create_persistent(struct dm_snapshot *s,
					      int blocksize,
					      offset_t extent_size,
					      void **error)
{
	return NULL;
}


/*
 * Implementation of the store for non-persistent snapshots.
 */
struct transient_c {
	offset_t next_free;
};

void destroy_transient(struct exception_store *store)
{
	kfree(store->context);
	kfree(store);
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

struct exception_store *dm_create_transient(struct dm_snapshot *s,
					    int blocksize, void **error)
{
	struct exception_store *store;
	struct transient_c *tc;

	store = kmalloc(sizeof(*store), GFP_KERNEL);
	if (!store) {
		DMWARN("out of memory.");
		return NULL;
	}

	memset(store, 0, sizeof(*store));
	store->destroy = destroy_transient;
	store->prepare_exception = prepare_transient;
	store->snap = s;

	tc = kmalloc(sizeof(struct transient_c), GFP_KERNEL);
	if (!tc) {
		kfree(store);
		return NULL;
	}

	tc->next_free = 0;
	store->context = tc;

	return store;
}

