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
#include <linux/device-mapper.h>

#include "dm.h"

/* Magic for persistent snapshots: "SnAp" - Feeble isn't it. */
#define SNAP_MAGIC 0x70416e53

/* Hard sector size used all over the kernel */
#define SECTOR_SIZE 512

/* The on-disk version of the metadata. Only applicable to
   persistent snapshots.
   There is no backward or forward compatibility implemented, snapshots
   with different disk versions than the kernel will not be usable. It is
   expected that "lvcreate" will blank out the start of the COW device
   before calling the snapshot constructor. */
#define SNAPSHOT_DISK_VERSION 1

/* Metadata format: (please keep this up-to-date!)
   Persistent snapshots have a 1 block header (see below for structure) at
   the very start of the device. The COW metadata starts at
   .start_of_exceptions.

   COW metadata is stored in blocks that are "extent-size" sectors long as
   an array of disk_exception structures in Little-Endian format.
   The last entry in this array has rsector_new set to 0 (this cannot be a
   legal redirection as the header is here) and if rsector_org has a value
   it is the sector number of the next COW metadata sector on the disk. if
   rsector_org is also zero then this is the end of the COW metadata.

   The metadata is written in hardblocksize lumps rather than in units of
   extents for efficiency so don't expect a whole extent to be zeroed out
   at any time.

   Non-persistent snapshots simple have redirected blocks stored
   (in chunk_size sectors) from hard block 1 to avoid inadvertantly
   creating a bad header.
*/

/*
 * Internal snapshot structure
 */
struct snapshot_c {
	struct dm_dev *origin_dev;     /* Original device (s/b a snapshot-origin) */
	struct dm_dev *cow_dev;        /* Device holding COW data */
        struct list_head list;         /* List of snapshots per Origin */
	unsigned int chunk_size;       /* Size of data blocks saved - must be a power of 2 */
	unsigned int chunk_size_mask;  /* Chunk size-1 for & operations */
        long   extent_size;            /* Size of extents used for COW blocks */
	int    full;                   /* 1 if snapshot is full (and therefore unusable) */
	int    persistent;             /* 1 if snapshot is is persistent (save metadata to disk) */
	unsigned long next_free_sector; /* Number of the next free sector for COW/data */
	unsigned long start_of_exceptions;    /* Where the metadata starts */
	unsigned long current_metadata_sector;/* Where we are currently writing the metadata */
	int    current_metadata_entry; /* Index into disk_cow array */
	int    current_metadata_number;/* Index into mythical extent array */
	int    highest_metadata_entry; /* Number of metadata entries in the disk_cow array */
	int    md_entries_per_block;   /* Number of metadata entries per hard disk block */
 	struct kiobuf *iobuf;          /* kiobuf for doing I/O to chunks and cows */
	struct kiobuf *cow_iobuf;      /* kiobuf for doing I/O to header & metadata */
	struct list_head *hash_table;  /* Hash table for looking up COW data */
	struct origin_list *origin;    /* So we can get at the locking rwsem */
	uint32_t hash_mask;
	uint32_t hash_size;
	int    need_cow;
	struct disk_exception *disk_cow; /* Disk extent with COW data in it. as an array of
					    exception tables. The first one points to the next
					    block of metadata or 0 if this is the last */
};

/* Exception in memory */
struct exception {
	struct list_head list; /* List of exceptions in this bucket */
	uint32_t rsector_org;
	uint32_t rsector_new;
	atomic_t ondisk;            /* Flag set when this COW block has actually hit the disk */
	struct   buffer_head *bh;   /* Chain of WRITE buffer heads to submit when this COW has completed */
	struct   snapshot_c  *snap; /* Pointer back to snapshot context */
};

/* An array of these is held in each disk block. LE format */
struct disk_exception {
	uint64_t rsector_org;
	uint64_t rsector_new;
};

/* Structure of a (persistent) snapshot header on disk. in LE format */
struct snap_disk_header {
	uint32_t magic;
	uint32_t version;           /* Simple, incrementing version. no backward compatibility */
	uint32_t chunk_size;        /* In 512 byte sectors */
	uint32_t extent_size;       /* In 512 byte sectors */
	uint64_t start_of_exceptions;
	uint32_t full;
};

static int write_metadata(struct snapshot_c *lc);

/* Size of the hash table for origin volumes. If we make this
   the size of the minors list then it should be nearly perfect */
#define ORIGIN_HASH_SIZE 256
#define ORIGIN_MASK      0xFF
#define ORIGIN_HASH_FN(x)  (MINOR(x) & ORIGIN_MASK)
#define EX_HASH_FN(sector, snap) ((sector/snap->chunk_size) & snap->hash_mask)

/* Hash table mapping origin volumes to lists of snapshots and
   a lock to protect it */
static struct list_head *snapshot_origins = NULL;
static struct rw_semaphore origin_hash_lock;

/* One of these per registered origin, held in the snapshot_origins hash */
struct origin_list
{
	kdev_t              origin_dev; /* The origin device */
	struct rw_semaphore lock;       /* To serialise access to the metadata */
	struct list_head    list;       /* List pointers for this list */
	struct list_head    snap_list;  /* List of snapshots for this origin */
};

/* Return the number of sectors in the device */
static inline int get_dev_size(kdev_t dev)
{
	int *sizes;

	sizes = blk_size[MAJOR(dev)];
	if (sizes)
		return sizes[MINOR(dev)]<<1;
	else
		return 0;
}

/* Return the list of snapshots for a given origin device.
   The origin_hash_lock must be held when calling this */
static struct origin_list *__lookup_snapshot_list(kdev_t origin)
{
        struct list_head *slist;
	struct list_head *snapshot_list;

	snapshot_list = &snapshot_origins[ORIGIN_HASH_FN(origin)];
	list_for_each(slist, snapshot_list) {
		struct origin_list *ol;
		ol = list_entry(slist, struct origin_list, list);

		if (ol->origin_dev == origin) {
			return ol;
		}
	}
	return NULL;
}


/* Add a new exception entry to the on-disk metadata */
static int update_metadata_block(struct snapshot_c *sc, unsigned long org, unsigned long new)
{
	int i = sc->current_metadata_entry++;
	unsigned long next_md_block = sc->current_metadata_sector;

	sc->current_metadata_number++;

	/* Update copy of disk COW */
	sc->disk_cow[i].rsector_org = cpu_to_le64(org);
	sc->disk_cow[i].rsector_new = cpu_to_le64(new);

	/* Have we filled this extent ? */
	if (sc->current_metadata_number >= sc->highest_metadata_entry) {
		/* Fill in pointer to next metadata extent */
		i++;
		sc->current_metadata_entry++;

		next_md_block = sc->next_free_sector;
		sc->next_free_sector += sc->extent_size;

		sc->disk_cow[i].rsector_org = cpu_to_le64(next_md_block);
		sc->disk_cow[i].rsector_new = 0;
	}

	/* Commit to disk */
	if (write_metadata(sc)) {
		sc->full = 1; /* Failed. don't try again */
		return -1;
	}

	/* Write a new (empty) metadata block if we are at the end of an existing
	   block so that read_metadata finds a terminating zero entry */
	if (sc->current_metadata_entry == sc->md_entries_per_block) {
		memset(sc->disk_cow, 0, PAGE_SIZE);
		sc->current_metadata_sector = next_md_block;

		/* If this is also the end of an extent then go back to the start */
		if (sc->current_metadata_number >= sc->highest_metadata_entry) {
			sc->current_metadata_number = 0;
		}
		else {
			int blocksize = get_hardsect_size(sc->cow_dev->dev);
			sc->current_metadata_sector += blocksize/SECTOR_SIZE;
		}

		sc->current_metadata_entry = 0;
		if (write_metadata(sc) != 0) {
			sc->full = 1;
			return -1;
		}
	}
	return 0;
}


/* Called when the copy I/O has finished */
static void copy_callback(copy_cb_reason_t reason, void *context, long arg)
{
	struct exception *ex = (struct exception *) context;
	struct buffer_head *bh;

	if (reason == COPY_CB_COMPLETE) {
		/* Update the metadata if we are persistent */
		if (ex->snap->persistent)
			update_metadata_block(ex->snap, ex->rsector_org, ex->rsector_new);

		atomic_set(&ex->ondisk, 1);

		/* Submit any pending write BHs */
		down_write(&ex->snap->origin->lock);
		bh = ex->bh;
		while (bh) {
			struct buffer_head *nextbh = bh->b_reqnext;
			bh->b_reqnext = NULL;
			generic_make_request(WRITE, bh);
			bh = nextbh;
		}
		ex->bh = NULL;
		up_write(&ex->snap->origin->lock);
	}

	/* Read/write error - snapshot is unusable */
	if (reason == COPY_CB_FAILED_WRITE || reason == COPY_CB_FAILED_READ) {
		DMERR("Error reading/writing snapshot\n");
		ex->snap->full = 1;
	}
}

/* Make a note of the snapshot and its origin so we can look it up when
   the origin has a write on it */
static int register_snapshot(kdev_t origin_dev, struct snapshot_c *snap)
{
	struct origin_list *ol;

	down_write(&origin_hash_lock);
	ol = __lookup_snapshot_list(origin_dev);

	if (!ol) {
		struct list_head *snapshot_list;

		/* New origin */
		ol = kmalloc(sizeof(*ol), GFP_KERNEL);
		if (!ol) {
			up_write(&origin_hash_lock);
			return 0;
		}

		/* Add this snapshot to the origin's list of snapshots */
		INIT_LIST_HEAD(&ol->snap_list);

		/* Initialise the struct */
		ol->origin_dev = origin_dev;
		init_rwsem(&ol->lock);

		/* Add this origin to the hash table */
		snapshot_list = &snapshot_origins[ORIGIN_HASH_FN(origin_dev)];
		list_add_tail(&ol->list, snapshot_list);
	}

	list_add_tail(&snap->list, &ol->snap_list);

	up_write(&origin_hash_lock);
	snap->origin = ol;
	return 1;
}

/* Return the exception data for a sector, or NULL if not remapped */
static struct exception *find_exception(struct snapshot_c *sc, uint32_t b_rsector)
{
	struct list_head *l = &sc->hash_table[EX_HASH_FN(b_rsector, sc)];
        struct list_head *slist;

	list_for_each(slist, l) {
		struct exception *et = list_entry(slist, struct exception, list);

		if (et->rsector_org == b_rsector - (b_rsector & sc->chunk_size_mask))
			return et;
	}
	return NULL;
}

/* Allocate a kiobuf. This is the only code nicked from the
   old snapshot driver and I've changed it anyway */
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

/* ...OK there's this too. */
static int calc_max_buckets(void)
{
	unsigned long mem;

	mem = num_physpages << PAGE_SHIFT;
	mem /= 50;
	mem /= sizeof(struct list_head);

	return mem;
}

/* Allocate room for a suitable hash table */
static int alloc_hash_table(struct snapshot_c *sc)
{
	int  i;
	int  hash_size;
	unsigned long cow_dev_size;
	unsigned long origin_dev_size;
	int  max_buckets;

        /* Calculate based on the size of the original volume
	   or the COW volume... */
	cow_dev_size = get_dev_size(sc->cow_dev->dev);
	origin_dev_size = get_dev_size(sc->origin_dev->dev);
	max_buckets = calc_max_buckets();

	hash_size = min(origin_dev_size, cow_dev_size) / sc->chunk_size;
	hash_size = min(hash_size, max_buckets);

	/* Round it down to a power of 2 */
	while (hash_size & (hash_size-1))
		hash_size &= (hash_size-1);

	sc->hash_mask = hash_size-1;
	sc->hash_size = hash_size;
	sc->hash_table = vmalloc(sizeof(struct list_head) * (hash_size));
	if (!sc->hash_table) return -1;

	for (i=0; i<hash_size; i++)
		INIT_LIST_HEAD(sc->hash_table + i);

	return 0;
}


/* Read in a chunk from the origin device */
static int read_blocks(struct kiobuf *iobuf, kdev_t dev, unsigned long start, int nr_sectors)
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

	status = brw_kiovec(READ, 1, &iobuf, dev, iobuf->blocks, blocksize);
	return (status != (nr_sectors << 9));
}

/* Write out blocks */
static int write_blocks(struct kiobuf *iobuf, kdev_t dev, unsigned long start, int nr_sectors)
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

	status = brw_kiovec(WRITE, 1, &iobuf, dev, iobuf->blocks, blocksize);
	return (status != (nr_sectors << 9));
}

/* Free all the allocated exception structures */
static void free_exception_table(struct snapshot_c *lc)
{
	int i;

	for (i=0; i < lc->hash_size; i++) {
		struct list_head *l = &lc->hash_table[i];
		struct list_head *entry, *temp;

		if (l) {
			list_for_each_safe(entry, temp, l) {
				struct exception *ex;
				ex = list_entry(entry, struct exception, list);
				list_del(&ex->list);
				kfree(ex);
			}
		}
	}
}

/* Add a new exception to the list */
static struct exception *add_exception(struct snapshot_c *sc, unsigned long org, unsigned long new)
{
	struct list_head *l = &sc->hash_table[EX_HASH_FN(org, sc)];
	struct exception *new_ex;

	new_ex = kmalloc(sizeof(struct exception), GFP_KERNEL);
	if (!new_ex) return NULL;

	new_ex->rsector_org = org;
	new_ex->rsector_new = new;
	new_ex->bh = 0;
	atomic_set(&new_ex->ondisk, 0);
	new_ex->snap = sc;

	list_add(&new_ex->list, l);

	return new_ex;
}

/* Read on-disk COW metadata and populate the hash table */
static int read_metadata(struct snapshot_c *lc)
{
	int status;
	int i;
	int entry = 0;
	int map_page = 0;
	int nr_sectors = lc->extent_size;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
	unsigned long cur_sector = lc->start_of_exceptions;
	unsigned long last_sector;
	unsigned long first_free_sector = 0;
	int entries_per_page = PAGE_SIZE / sizeof(struct disk_exception);
	struct disk_exception *cow_block;
	struct kiobuf *read_iobuf;
	int err = 0;

	/* Allocate our own iovec for this operation 'cos the others
	   are way too small */
	if (alloc_kiovec(1, &read_iobuf)) {
		DMERR("Error allocating iobuf for %s\n", kdevname(lc->cow_dev->dev));
		return -1;
	}

	if (alloc_iobuf_pages(read_iobuf, lc->extent_size)) {
		DMERR("Error allocating iobuf space for %s\n", kdevname(lc->cow_dev->dev));
		free_kiovec(1, &read_iobuf);
		return -1;
	}
	cow_block = page_address(read_iobuf->maplist[0]);

	do
	{
		first_free_sector = max(first_free_sector, cur_sector+lc->extent_size);
		status = read_blocks(read_iobuf, lc->cow_dev->dev, cur_sector, nr_sectors);
		if (status == 0) {

			map_page = 0;
			entry = 0;

			cow_block = page_address(read_iobuf->maplist[0]);

			/* Now populate the hash table from this data */
			for (i=0; i <= lc->highest_metadata_entry &&
				  cow_block[entry].rsector_new != 0; i++) {

				add_exception(lc,
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
			DMERR("Error reading COW metadata for %s\n", kdevname(lc->cow_dev->dev));
			err = -1;
			goto ret_free;
		}
		last_sector = cur_sector;
		cur_sector = le64_to_cpu(cow_block[entry].rsector_org);

	} while (cur_sector != 0);

	lc->persistent = 1;
	lc->current_metadata_sector = last_sector +
		                      map_page*PAGE_SIZE/SECTOR_SIZE +
                                      entry/(SECTOR_SIZE/sizeof(struct disk_exception));
	lc->current_metadata_entry  = entry;
	lc->current_metadata_number = i;
	lc->next_free_sector = first_free_sector;

	/* Copy last block into cow_iobuf */
	memcpy(lc->disk_cow, (char *)((long)&cow_block[entry] - ((long)&cow_block[entry] & (blocksize-1))), blocksize);

 ret_free:
	unmap_kiobuf(read_iobuf);
	free_kiovec(1, &read_iobuf);

	return err;
}

/* Read the snapshot volume header, returns 0 only if it read OK and
   it was valid. returns 1 if no header was found, -1 on error.
   All fields are checked against the snapshot structure itself to
   make sure we don't corrupt the data */
static int read_header(struct snapshot_c *lc)
{
	int status;
	struct snap_disk_header *header;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
	unsigned long devsize;

	/* Get it */
	status = read_blocks(lc->cow_iobuf, lc->cow_dev->dev, 0L, blocksize/SECTOR_SIZE);
	if (status != 0) {
		DMERR("Snapshot dev %s error reading header\n", kdevname(lc->cow_dev->dev));
		return -1;
	}

	header = (struct snap_disk_header *)page_address(lc->cow_iobuf->maplist[0]);

	/* Check the magic. It's OK if this fails, we just create a new snapshot header
	   and start from scratch */
	if (le32_to_cpu(header->magic) != SNAP_MAGIC) {
		return 1;
	}

	/* Check the version matches */
	if (le32_to_cpu(header->version) != SNAPSHOT_DISK_VERSION) {
		DMWARN("Snapshot dev %s version mismatch. Stored: %d, driver: %d\n",
		       kdevname(lc->cow_dev->dev), le32_to_cpu(header->version), SNAPSHOT_DISK_VERSION);
		return -1;
	}

	/* Check the chunk sizes match */
	if (le32_to_cpu(header->chunk_size) != lc->chunk_size) {
		DMWARN("Snapshot dev %s chunk size mismatch. Stored: %d, requested: %d\n",
		       kdevname(lc->cow_dev->dev), le32_to_cpu(header->chunk_size), lc->chunk_size);
		return -1;
	}

	/* Check the extent sizes match */
	if (le32_to_cpu(header->extent_size) != lc->extent_size) {
		DMWARN("Snapshot dev %s extent size mismatch. Stored: %d, requested: %ld\n",
		       kdevname(lc->cow_dev->dev), le32_to_cpu(header->extent_size), lc->extent_size);
		return -1;
	}

	/* Get the rest of the data */
	lc->start_of_exceptions = le64_to_cpu(header->start_of_exceptions);
	if (header->full) {
		DMWARN("Snapshot dev %s is full. It cannot be used\n", kdevname(lc->cow_dev->dev));
		lc->full = 1;
		return -1;
	}

	/* Validate against the size of the volume */
	devsize = get_dev_size(lc->cow_dev->dev);
	if (lc->start_of_exceptions > devsize) {
		DMWARN("Snapshot metadata error on %s. start exceptions > device size (%ld > %ld)\n",
		       kdevname(lc->cow_dev->dev), lc->start_of_exceptions, devsize);
		return -1;
	}

	/* Read metadata into the hash table and update pointers */
	return read_metadata(lc);
}

/* Write (or update) the header. The only time we should need to do
   an update is when the snapshot becomes full. */
static int write_header(struct snapshot_c *lc)
{
	struct snap_disk_header *header;
	struct kiobuf *head_iobuf;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
	int status;

	/* Allocate our own iobuf for this so we don't corrupt any
	   of the other writes that may be going on */
	if (alloc_kiovec(1, &head_iobuf)) {
		DMERR("Error allocating iobuf for header on %s\n", kdevname(lc->cow_dev->dev));
		return -1;
	}

	if (alloc_iobuf_pages(head_iobuf, PAGE_SIZE/SECTOR_SIZE)) {
		DMERR("Error allocating iobuf space for header on %s\n", kdevname(lc->cow_dev->dev));
		free_kiovec(1, &head_iobuf);
		return -1;
	}

	header = (struct snap_disk_header *)page_address(head_iobuf->maplist[0]);

	header->magic       = cpu_to_le32(SNAP_MAGIC);
	header->version     = cpu_to_le32(SNAPSHOT_DISK_VERSION);
	header->chunk_size  = cpu_to_le32(lc->chunk_size);
	header->extent_size = cpu_to_le32(lc->extent_size);
	header->full        = cpu_to_le32(lc->full);

	header->start_of_exceptions = cpu_to_le64(lc->start_of_exceptions);

	/* Must write at least a full block */
	status = write_blocks(head_iobuf, lc->cow_dev->dev, 0, blocksize/SECTOR_SIZE);

	unmap_kiobuf(head_iobuf);
	free_kiovec(1, &head_iobuf);
	return status;
}


/* Write the latest COW metadata block */
static int write_metadata(struct snapshot_c *lc)
{
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
	int writesize = blocksize/SECTOR_SIZE;

	if (write_blocks(lc->cow_iobuf, lc->cow_dev->dev, lc->current_metadata_sector, writesize) != 0) {
		DMERR("Error writing COW block\n");
		return -1;
	}

	return 0;
}

static int setup_persistent_snapshot(struct snapshot_c *lc, int blocksize, void **context)
{
	int status;
	int i;
	int cow_sectors;

	lc->highest_metadata_entry = (lc->extent_size*SECTOR_SIZE) / sizeof(struct disk_exception) - 1;
	lc->md_entries_per_block   = blocksize / sizeof(struct disk_exception);

	/* Allocate and set up iobuf for metadata I/O*/
	*context = "Unable to allocate COW iovec";
	if (alloc_kiovec(1, &lc->cow_iobuf))
		return -1;

	/* Allocate space for the COW buffer. It should be at least PAGE_SIZE. */
	cow_sectors = blocksize/SECTOR_SIZE + PAGE_SIZE/SECTOR_SIZE;
	*context = "Unable to allocate COW I/O buffer space";
	if (alloc_iobuf_pages(lc->cow_iobuf, cow_sectors)) {
		free_kiovec(1, &lc->cow_iobuf);
		return -1;
	}

	for (i=0; i < lc->cow_iobuf->nr_pages; i++) {
		memset(page_address(lc->cow_iobuf->maplist[i]), 0, PAGE_SIZE);
	}

	lc->disk_cow = page_address(lc->cow_iobuf->maplist[0]);

	*context = "Error in disk header";
	/* Check for a header on disk and create a new one if not */
	if ( (status = read_header(lc)) == 1) {

		/* Write a new header */
		lc->start_of_exceptions = lc->next_free_sector;
		lc->next_free_sector += lc->extent_size;
		lc->current_metadata_sector = lc->start_of_exceptions;
		lc->current_metadata_entry  = 0;
		lc->current_metadata_number = 0;

		*context = "Unable to write snapshot header";
		if (write_header(lc) != 0) {
			DMERR("Error writing header to snapshot volume %s\n",
			      kdevname(lc->cow_dev->dev));
			goto free_ret;
		}

		/* Write a blank metadata block to the device */
		if (write_metadata(lc) != 0) {
			DMERR("Error writing initial COW table to snapshot volume %s\n",
			      kdevname(lc->cow_dev->dev));
			goto free_ret;
		}
	}

	/* There is a header but it doesn't match - fail
	   so we don't destroy what might be useful data on disk.
	   If the user really wants to use this COW device for a snapshot then the first
	   sector should be zeroed out first */
	if (status == -1)
		goto free_ret;

	return 0;

 free_ret:
	unmap_kiobuf(lc->cow_iobuf);
	free_kiovec(1, &lc->cow_iobuf);
	return -1;
}

/*
 * Construct a snapshot mapping: <origin_dev> <COW-dev> <p/n> <chunk-size> <extent-size>
 */
static int snapshot_ctr(struct dm_table *t, offset_t b, offset_t l,
			int argc, char **argv, void **context)
{
	struct snapshot_c *lc;
	unsigned long chunk_size;
	unsigned long extent_size;
	int r = -EINVAL;
	char *persistent;
	char *origin_path;
	char *cow_path;
	char *value;
	int blocksize;

	if (argc < 5) {
		*context = "dm-snapshot: Not enough arguments";
		return -EINVAL;
	}

	origin_path = argv[0];
	cow_path    = argv[1];
	persistent  = argv[2];

	*context = "Persistent flag is not P or N";
	if ((*persistent & 0x5f) != 'P' &&
	    (*persistent & 0x5f) != 'N')
		goto bad;

	chunk_size = simple_strtoul(argv[3], &value, 10);
	if (chunk_size == 0 || value == NULL) {
		*context = "Invalid chunk size";
		goto bad;
	}

	extent_size = simple_strtoul(argv[4], &value, 10);
	if (extent_size == 0 || value == NULL) {
		*context = "Invalid extent size";
		goto bad;
	}

	*context = "Cannot allocate snapshot context private structure";
	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL)
		goto bad;

	*context = "Cannot get origin device";
	r = dm_table_get_device(t, origin_path, 0, 0, &lc->origin_dev);
	if (r)
		goto bad_free;

	*context = "Cannot get COW device";
	r = dm_table_get_device(t, cow_path, 0, 0, &lc->cow_dev);
	if (r) {
		dm_table_put_device(t, lc->origin_dev);
		goto bad_free;
	}

	/* Validate the extent and chunk sizes against the device block size */
	blocksize = get_hardsect_size(lc->cow_dev->dev);
	if (chunk_size % (blocksize/SECTOR_SIZE)) {
		*context = "Chunk size is not a multiple of device blocksize";
		goto bad_putdev;
	}

	if (extent_size % (blocksize/SECTOR_SIZE)) {
		*context = "Extent size is not a multiple of device blocksize";
		goto bad_putdev;
	}

	/* Check the sizes are small enough to fit in one kiovec */
	if (chunk_size > KIO_MAX_SECTORS) {
		*context = "Chunk size is too big";
		goto bad_putdev;
	}

	if (extent_size > KIO_MAX_SECTORS) {
		*context = "Extent size is too big";
		goto bad_putdev;
	}

	/* Check chunk_size is a power of 2 */
	if (chunk_size != 1 << (ffs(chunk_size)-1)) {
		*context = "Chunk size is not a power of 2";
		r = -EINVAL;
		goto bad_putdev;
	}

        lc->chunk_size = chunk_size;
        lc->chunk_size_mask = chunk_size-1;
	lc->extent_size = extent_size;
	lc->next_free_sector = blocksize/SECTOR_SIZE; /* Leave the first block alone */
	lc->need_cow  = 0;
	lc->full      = 0;
	lc->disk_cow  = NULL;

	/* Allocate hash table for COW data */
	r = -ENOMEM;
	*context = "Unable to allocate has table space";
	if (alloc_hash_table(lc) == -1)
		goto bad_putdev;

	/* Allocate and set up iobuf */
	*context = "Unable to allocate iovec";
	if (alloc_kiovec(1, &lc->iobuf))
		goto bad_free1;

	*context = "Unable to allocate I/O buffer space";
	if (alloc_iobuf_pages(lc->iobuf, chunk_size))
		goto bad_free2;

	/* Check the persistent flag - done here because we need the iobuf
	   to check the LV header */
	if ((*persistent & 0x5f) == 'P') {
		lc->persistent = 1;
	}
	else {
		lc->persistent = 0;
	}

	/* For a persistent snapshot allocate the COW iobuf and set associated variables */
	if (lc->persistent) {
		if (setup_persistent_snapshot(lc, blocksize, context))
			goto bad_free3;
	}

	/* Flush IO to the origin device */
	/* TODO: VFS lock sync too */
	fsync_dev(lc->origin_dev->dev);
#if LVM_VFS_ENHANCEMENT
	fsync_dev_lockfs(lc->origin_dev->dev);
	unlockfs(lc->origin_dev->dev);
#endif

        /* Add snapshot to the list of snapshots for this origin */
	r = -EINVAL;
	*context = "Cannot register snapshot origin";
	if (!register_snapshot(lc->origin_dev->dev, lc))
	    goto bad_free4;

	*context = lc;
	return 0;

 bad_free4:
	if (lc->persistent) {
		unmap_kiobuf(lc->cow_iobuf);
		free_kiovec(1, &lc->cow_iobuf);
	}
 bad_free3:
	unmap_kiobuf(lc->iobuf);
 bad_free2:
	free_kiovec(1, &lc->iobuf);
 bad_free1:
	vfree(lc->hash_table);
 bad_putdev:
	dm_table_put_device(t, lc->cow_dev);
	dm_table_put_device(t, lc->origin_dev);
 bad_free:
	kfree(lc);
 bad:
	return r;
}

static void snapshot_dtr(struct dm_table *t, void *c)
{
	struct snapshot_c *lc = (struct snapshot_c *) c;

	/* Unhook from the list */
	list_del(&lc->list);

	/* Deallocate memory used */
	free_exception_table(lc);
	unmap_kiobuf(lc->iobuf);
	free_kiovec(1, &lc->iobuf);
	if (lc->persistent) {
		unmap_kiobuf(lc->cow_iobuf);
		free_kiovec(1, &lc->cow_iobuf);
	}

	vfree(lc->hash_table);
	dm_table_put_device(t, lc->origin_dev);
	dm_table_put_device(t, lc->cow_dev);
	kfree(c);
}

static int snapshot_map(struct buffer_head *bh, int rw, void *context)
{
	struct exception *ex;
	struct snapshot_c *lc = (struct snapshot_c *) context;
	int ret = 1;

        /* Full snapshots are not usable */
	if (lc->full)
		return -1;

	/* Write to snapshot - higher level takes care of RW/RO flags so we should only
	   get this if we are writeable */
	if (rw == WRITE) {

		down_write(&lc->origin->lock);

		/* If the block is already remapped - use that, else remap it */
		ex = find_exception(context, bh->b_rsector);
		if (ex) {
			if (atomic_read(&ex->ondisk)) {
				bh->b_rdev = lc->cow_dev->dev;
				bh->b_rsector = ex->rsector_new + (bh->b_rsector & lc->chunk_size_mask);
			}
			else {
				/* Exception has not been committed to disk - save this bh */
				bh->b_reqnext = ex->bh;
				ex->bh = bh;
				up_write(&lc->origin->lock);
				return 0;
			}
		}
		else {
			unsigned long read_start = bh->b_rsector - (bh->b_rsector & lc->chunk_size_mask);
			unsigned long devsize = get_dev_size(lc->cow_dev->dev);
			unsigned long reloc_sector;

			/* Check there is enough space */
			if (lc->next_free_sector + lc->chunk_size >= devsize) {
				DMWARN("Snapshot %s is full\n", kdevname(lc->cow_dev->dev));
				lc->full = 1;
				write_header(lc);
				up_write(&lc->origin->lock);
				return -1;
			}

			/* Update the exception table */
			reloc_sector = lc->next_free_sector;
			lc->next_free_sector += lc->chunk_size;
			ex = add_exception(lc, read_start, reloc_sector);
			if (!ex) {
				DMERR("Snapshot %s error adding new exception entry\n", kdevname(lc->cow_dev->dev));
				/* Error here - treat it as full */
				lc->full = 1;
				write_header(lc);
				up_write(&lc->origin->lock);
				return -1;
			}

			/* Get kcopyd to do the work */
			dm_blockcopy(read_start, reloc_sector, lc->chunk_size,
				     lc->origin_dev->dev, lc->cow_dev->dev, 0,
				     copy_callback, ex);

			/* Update the bh bits so the write goes to the newly remapped volume...
			   after the COW has completed */
			bh->b_rdev = lc->cow_dev->dev;
			bh->b_rsector = lc->next_free_sector + (bh->b_rsector & lc->chunk_size_mask);

			bh->b_reqnext = ex->bh;
			ex->bh = bh;

			/* Tell the upper layers we have control of the BH now */
			ret = 0;
		}

		up_write(&lc->origin->lock);
	}
	else {
		/* Do reads */
		down_read(&lc->origin->lock);

		/* By default reads come from the origin */
		bh->b_rdev = lc->origin_dev->dev;

		/* Unless it has been remapped */
		ex = find_exception(context, bh->b_rsector);
		if (ex && atomic_read(&ex->ondisk)) {

			bh->b_rdev = lc->cow_dev->dev;
			bh->b_rsector = ex->rsector_new + (bh->b_rsector & lc->chunk_size_mask);
		}
		up_read(&lc->origin->lock);
	}

	return ret;
}

/* Called on a write from the origin driver */
int dm_do_snapshot(struct dm_dev *origin, struct buffer_head *bh)
{
	struct list_head *snap_list;
	struct origin_list *ol;
	int ret = 1;

	down_read(&origin_hash_lock);
	ol = __lookup_snapshot_list(origin->dev);
	up_read(&origin_hash_lock);

	if (ol) {
		struct list_head *origin_snaps = &ol->snap_list;
		struct snapshot_c *lock_snap;

		/* Lock the metadata */
		lock_snap = list_entry(origin_snaps->next, struct snapshot_c, list);
		down_write(&lock_snap->origin->lock);

		/* Do all the snapshots on this origin */
		list_for_each(snap_list, origin_snaps) {
			struct snapshot_c *snap;
			struct exception  *ex;
			snap = list_entry(snap_list, struct snapshot_c, list);

			/* Ignore full snapshots */
			if (snap->full)
				continue;

			/* Check exception table to see if block is already remapped in this
			   snapshot and mark the snapshot as needing a COW if not */
			ex = find_exception(snap, bh->b_rsector);
			if (!ex) {
				offset_t dev_size;

                                /* Check for full snapshot. Doing the size calculation here means that
				   the COW device can be resized without us being told */
				dev_size = get_dev_size(snap->cow_dev->dev);
				if (snap->next_free_sector + snap->chunk_size >= dev_size) {
					        /* Snapshot is full, we can't use it */
						DMWARN("Snapshot %s is full\n",
						       kdevname(snap->cow_dev->dev));
						snap->full = 1;
						/* Mark it full on the device */
						write_header(snap);
						continue;
				}
				else {
					/* Update exception table */
					unsigned long reloc_sector;
					unsigned long read_start = bh->b_rsector - (bh->b_rsector & snap->chunk_size_mask);

					reloc_sector = snap->next_free_sector;
					snap->next_free_sector += snap->chunk_size;
					ex = add_exception(snap, bh->b_rsector, reloc_sector);
					if (!ex) {
						DMERR("Snapshot %s error adding new exception entry\n",
						      kdevname(snap->cow_dev->dev));
						/* Error here - treat it as full */
						snap->full = 1;
						write_header(snap);
						continue;
					}

					/* Get kcopyd to do the copy */
					dm_blockcopy(read_start, reloc_sector, snap->chunk_size,
						     snap->origin_dev->dev, snap->cow_dev->dev, 0,
						     copy_callback, ex);
				}
			}
			/* If the exception is in flight then defer the BH -
			   but don't add it twice! */
			if (ex && !atomic_read(&ex->ondisk) && !ret) {
				bh->b_reqnext = ex->bh;
				ex->bh = bh;
				ret = 0;
			}
		}
		up_write(&lock_snap->origin->lock);
	}
	return ret;
}


static struct target_type snapshot_target = {
	name:	"snapshot",
	module:	THIS_MODULE,
	ctr:	snapshot_ctr,
	dtr:	snapshot_dtr,
	map:	snapshot_map,
	err:	NULL
};

static int __init snapshot_init(void)
{
	int r = dm_register_target(&snapshot_target);

	if (r < 0)
		DMERR("Device mapper: Snapshot: register failed %d\n", r);
	else {
		snapshot_origins = kmalloc(ORIGIN_HASH_SIZE * sizeof(struct list_head), GFP_KERNEL);
		if (snapshot_origins == NULL) {
			DMERR("Device mapper: Snapshot: unable to allocate memory\n");
			r = -1;
		}
		else {
			/* initialise the origin->snapshot hash table */
			int i;
			for (i=0; i<ORIGIN_HASH_SIZE; i++)
				INIT_LIST_HEAD(snapshot_origins + i);
			init_rwsem(&origin_hash_lock);
		}
	}

	return r;
}

static void snapshot_exit(void)
{
	int r = dm_unregister_target(&snapshot_target);

	if (r < 0)
		DMERR(
		       "Device mapper: Snapshot: unregister failed %d\n", r);

	if (snapshot_origins)
		kfree(snapshot_origins);
}

module_init(snapshot_init);
module_exit(snapshot_exit);

MODULE_AUTHOR("Patrick Caulfield <caulfield@sistina.com>");
MODULE_DESCRIPTION("Device Mapper: Snapshots");
MODULE_LICENSE("GPL");

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
