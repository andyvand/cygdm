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

#define SECTOR_SIZE 512

/*
TODOs:
- put some limit on the COW hash-table size (and figure out why that +1 needs to be there)
- use a hash-table for the list of origin/snaps rather than a list
- writeable snapshots
- test with >1 snapshot (and differing chunk sizes)
- check iobuf allocation cos it's probably wrong.
- check chunk size is compatible with hard sector size (and other snapshots)
- allow user to change the COW block size (current hardwired to hardsector size) Use extent size??
- lots of testing
*/

/* Magic for persistent snapshots: "SnAp" */
#define SNAP_MAGIC 0x70416e53

/*
 * Snapshot:
 */
struct snapshot_c {
	struct dm_dev *origin_dev;     /* Original device (s/b a snapshot-origin) */
	struct dm_dev *cow_dev;        /* Device holding COW data */
        struct list_head list;         /* List of snapshots per Origin */
	unsigned int chunk_size;       /* Size of data blocks saved */
        long   extent_size;            /* Size of extents used */
	int    full;                   /* 1 if snapshot is full (and therefore unusable) */
	int    persistent;             /* 1 if snapshot is is persistent (save metadata to disk) */
	long   next_free_sector;       /* Number of the next free sector for COW/data */
	long   start_of_exceptions;    /* Where the metadata starts */
	long   current_metadata_sector;/* Where we are currently writing the metadata */
	int    current_metadata_entry; /* Pointer into disk_cow array */
	int    highest_metadata_entry; /* Number of metadata entries in the disk_cow array */
	struct kiobuf *iobuf;          /* kiobuf for doing I/O to chunks and cows */
	struct list_head *hash_table;  /* Hash table for looking up data */
	uint32_t hash_mask;
	uint32_t hash_size;
	int    need_cow;
	struct disk_exception *disk_cow; /* Disk block with COW data in it. as an array of
					    exception tables. The first one points to the next
					    block of metadata or 0 if this is the last */
};

struct exception {
	struct list_head list; /* List of exceptions in this bucket */
	uint32_t rsector_org;
	uint32_t rsector_new;
};

/* An array of these is held in each disk block */
struct disk_exception {
	uint64_t rsector_org;
	uint64_t rsector_new;
};

/* Structure of a (persistent) snapshot header on disk. in LE format */
struct snap_disk_header {
	uint32_t magic;
	uint32_t chunk_size;
	uint64_t next_free_sector;
	uint64_t start_of_exceptions;
	uint32_t full;
};

static int write_metadata(struct snapshot_c *lc);

static inline char *next_token(char **p)
{
	static const char *delim = " \t";
	char *r;

	do {
		r = strsep(p, delim);
	} while (r && *r == 0);

	return r;
}

/* TODO: Make this a hash table */
static LIST_HEAD(snapshot_list);
struct origin_list
{
	kdev_t           origin_dev; /* The origin device */
	struct list_head list;       /* List pointers for this list */
	struct list_head snap_list;  /* List of snapshots for this origin */
};

/* TODO Make this a hash table */
static struct list_head *lookup_snapshot_list(kdev_t origin)
{
        struct list_head *slist;

	list_for_each(slist, &snapshot_list) {
		struct origin_list *ol;
		ol = list_entry(slist, struct origin_list, list);

		if (ol->origin_dev == origin) {
			return &ol->snap_list;
		}
	}
	return NULL;
}

/* Return the exception data for a sector, or NULL if not remapped */
static struct exception *find_exception(struct snapshot_c *sc, uint32_t b_rsector)
{
	struct list_head *l = &sc->hash_table[(b_rsector/sc->chunk_size) & sc->hash_mask];
        struct list_head *slist;

	printk(KERN_INFO "PJC: find_exception: looking for %d, bucket %d\n", b_rsector, (b_rsector/sc->chunk_size) & sc->hash_mask);

	list_for_each(slist, l) {
		struct exception *et = list_entry(slist, struct exception, list);
//		printk(KERN_INFO "PJC: find_exception: looking for %d(%d), found %d\n", b_rsector, b_rsector - (b_rsector % sc->chunk_size), et->rsector_org);
		if (et->rsector_org == b_rsector - (b_rsector % sc->chunk_size))
			return et;
	}
	return NULL;
}

/* Allocate room for a suitable hash table */
static int alloc_hash_table(struct snapshot_c *sc)
{
	int  i;
	int  hash_size;
	int *sizes;
	long cow_dev_size;
	long origin_dev_size = cow_dev_size = 128*sc->chunk_size;

        /* Calculate based on the size of the original volume
	   or the COW volume... */
	sizes = blk_size[MAJOR(sc->cow_dev->dev)];
	if (sizes) cow_dev_size = sizes[MINOR(sc->cow_dev->dev)]<<1;

	sizes = blk_size[MAJOR(sc->origin_dev->dev)];
	if (sizes) origin_dev_size = sizes[MINOR(sc->origin_dev->dev)]<<1;

	hash_size = min(origin_dev_size, cow_dev_size) / sc->chunk_size;

	/* Round it down to a power of 2 */
	while (hash_size & (hash_size-1))
		hash_size &= (hash_size-1);

	printk(KERN_INFO "PJC: hash size is %d\n", hash_size);

	sc->hash_mask = hash_size-1;
	sc->hash_size = hash_size;
	sc->hash_table = vmalloc(sizeof(struct list_head) * (hash_size+1));
	if (!sc->hash_table) return -1;

	for (i=0; i<=hash_size; i++)
		INIT_LIST_HEAD(sc->hash_table + i);

	return 0;
}

/* Make a note of the snapshot and it's origin so we can look it up when
   the origin has a write on it */
static int register_snapshot(kdev_t origin_dev, struct snapshot_c *context)
{
	// Just use a list for now....this will be a hash table
        struct list_head *sl = (struct list_head *)lookup_snapshot_list(origin_dev);
	if (sl) {
		/* Add snapshot to an existing origin */
		list_add_tail(sl, &context->list);
	}
	else {
		/* New origin */
		struct origin_list *ol = kmalloc(sizeof(*ol), GFP_KERNEL);
		if (!ol) return 0;

		/* Add this snapshot to the origin's list of snapshots */
		INIT_LIST_HEAD(&ol->snap_list);
		list_add_tail(&context->list, &ol->snap_list);

		/* Add this origin to the list of origins */
		ol->origin_dev = origin_dev;
		list_add_tail(&ol->list, &snapshot_list);
	}

	return 1;
}


/* Allocate the kiobuf. This is the only code nicked from the
   old snapshot driver */
int alloc_iobuf_pages(struct kiobuf *iobuf)
{
	int bytes, nr_pages, err, i;

	bytes = (KIO_MAX_SECTORS << (PAGE_SHIFT-9)) * SECTOR_SIZE;
	nr_pages = (bytes + ~PAGE_MASK) >> PAGE_SHIFT;
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

/* Read in a chunk from the origin device */
static int read_blocks(struct snapshot_c *lc, kdev_t dev, long start, int nr_sectors)
{
	int i, sectors_per_block, nr_blocks;
	unsigned long blocks[KIO_MAX_SECTORS];
	int blocksize = get_hardsect_size(lc->origin_dev->dev);
	int status;

	sectors_per_block = blocksize / SECTOR_SIZE;

	nr_blocks = nr_sectors / sectors_per_block;
	start /= sectors_per_block;

	for (i = 0; i < nr_blocks; i++)
		blocks[i] = start++;

	lc->iobuf->length = nr_sectors << 9;

	status = brw_kiovec(READ, 1, &lc->iobuf, dev,
			    blocks, blocksize);
	return (status != (nr_sectors << 9));
}

/* Write out blocks - we only ever write to the COW device
   so we don't expect the kdev_t as an arg */
static int write_blocks(struct snapshot_c *lc, long start, int nr_sectors, struct kiobuf *iobuf)
{
	int i, sectors_per_block, nr_blocks;
	unsigned long blocks[KIO_MAX_SECTORS];
	int blocksize = get_hardsect_size(lc->origin_dev->dev);
	int status;

	sectors_per_block = blocksize / SECTOR_SIZE;

	nr_blocks = nr_sectors / sectors_per_block;
	start /= sectors_per_block;

	for (i = 0; i < nr_blocks; i++)
		blocks[i] = start++;

	iobuf->length = nr_sectors << 9;

	status = brw_kiovec(WRITE, 1, &iobuf, lc->cow_dev->dev,
			    blocks, blocksize);
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
static int add_exception(struct snapshot_c *sc, unsigned long org, unsigned long new)
{
	struct list_head *l = &sc->hash_table[(org/sc->chunk_size) & sc->hash_mask];
	struct exception *new_ex;

	new_ex = kmalloc(sizeof(struct exception), GFP_KERNEL);
	if (!new_ex) return -1;

	new_ex->rsector_org = org;
	new_ex->rsector_new = new;

	printk(KERN_INFO "PJC: add_exception: storing %d, bucket %d\n", new_ex->rsector_org, (new_ex->rsector_org/sc->chunk_size) & sc->hash_mask);
	list_add(&new_ex->list, l);

	/* Add to the on-disk metadata */
	if (sc->persistent) {
		int i = sc->current_metadata_entry++;
		long next_md_block = 0;
		int blocksize = get_hardsect_size(sc->cow_dev->dev);

		/* Update copy of disk COW */
		sc->disk_cow[i].rsector_org = org;
		sc->disk_cow[i].rsector_new = new;

		/* Have we filled this block ? */
		if (i >= sc->highest_metadata_entry) {
			/* Fill in pointer to next metadata block */
			next_md_block = sc->next_free_sector + blocksize/SECTOR_SIZE;
			sc->disk_cow[0].rsector_new = next_md_block;
		}

		/* Commit to disk */
		if (write_metadata(sc) != 0)
			return -1;

		/* Write a new (empty) metadata block */
		if (i >= sc->highest_metadata_entry) {

			memset(sc->disk_cow, 0, blocksize);
			sc->current_metadata_entry = 1;
			sc->current_metadata_sector = next_md_block;

			if (write_metadata(sc) != 0)
				return -1;
		}
	}

	return 0;
}


/* Read on-disk COW metadata and populate the hash table */
static int read_metadata(struct snapshot_c *lc)
{
	int status;
	int i;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
	int nr_sectors = blocksize/SECTOR_SIZE;
	long cur_sector = lc->start_of_exceptions;

	/* Clear the persistent flag so that add_exception() doesn't try to rewrite the table
	   while we are populating it and also to make the snapshot non-persistent in case of
	   a write error. */
	lc->persistent = 0;
	do
	{
		status = read_blocks(lc, lc->cow_dev->dev, cur_sector, nr_sectors);
		if (status == 0) {
			/* Copy it to the allocated block */
			for (i=0; i<nr_sectors; i++) {
				memcpy(lc->disk_cow + (i*SECTOR_SIZE),
				       page_address(lc->iobuf->maplist[i]), SECTOR_SIZE);
			}

			/* Now populate the hash table from this data */
			for (i=1; i<blocksize/sizeof(struct disk_exception) &&
				     lc->disk_cow[i].rsector_new != 0; i++) {
				add_exception(lc, lc->disk_cow[i].rsector_org, lc->disk_cow[i].rsector_new);
			}
		}
		else {
			printk(KERN_WARNING "Error reading COW metadata for %x\n", lc->cow_dev->dev);
			return -1;
		}
		cur_sector = lc->disk_cow[0].rsector_new;
	} while (cur_sector != 0);

	lc->persistent = 1;
	lc->current_metadata_sector = cur_sector;
	lc->current_metadata_entry = i;

	printk(KERN_INFO "PJC: Read metadata\n");
	return 0;
}

/* Read the snapshot volume header, returns 0 only if it read OK and
   it was valid. The snapshot_c struct is filled in. */
static int read_header(struct snapshot_c *lc)
{
	int status;
	struct snap_disk_header *header;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);

	status = read_blocks(lc, lc->cow_dev->dev, 0L, blocksize/SECTOR_SIZE);
	if (status != 0) {
		printk(KERN_INFO "PJC: dev %x error reading header\n", lc->cow_dev->dev);
		return -1;
	}

	header = (struct snap_disk_header *)page_address(lc->iobuf->maplist[0]);

	/* Check the magic */
	if (le32_to_cpu(header->magic) != SNAP_MAGIC) {
		printk(KERN_INFO "PJC: dev %x magic number wrong: got %x\n", lc->cow_dev->dev, header->magic);
		return -1;
	}

	/* Check the chunk sizes match */
	if (le32_to_cpu(header->chunk_size) != lc->chunk_size) {
		printk(KERN_INFO "Snapshot dev %x chunk size mismatch. Stored: %d, requested: %d\n",
		       lc->cow_dev->dev, le32_to_cpu(header->chunk_size), lc->chunk_size);
		return -1;
	}

	/* Get the rest of the data */
	lc->next_free_sector = le64_to_cpu(header->next_free_sector);
	lc->start_of_exceptions = le64_to_cpu(header->start_of_exceptions);
	if (header->full) {
		printk(KERN_INFO "Snapshot dev %x is full. It cannot be used\n", lc->cow_dev->dev);
		lc->full = 1;
		return -1;
	}

	/* TODO: Validate those against the size of the volume */

	/* Read metadata into the hash table and update pointers */
	return read_metadata(lc);
}

/* Write (or update) the header. The only time we should need to do
   an update is when the snapshot becomes full */
static int write_header(struct snapshot_c *lc)
{
	struct snap_disk_header *header;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);

	/* TODO: Allocate a page for this so we don't destroy any read data
	   that need to be written to other (non-full) snapshots */
	header = (struct snap_disk_header *)page_address(lc->iobuf->maplist[0]);

	header->magic = cpu_to_le32(SNAP_MAGIC);
	header->chunk_size = cpu_to_le32(lc->chunk_size);
	header->full = cpu_to_le32(lc->full);

	header->next_free_sector = cpu_to_le64(lc->next_free_sector);
	header->start_of_exceptions = cpu_to_le64(lc->start_of_exceptions);

	/* Must write at least a full block */
	return write_blocks(lc, 0, blocksize/SECTOR_SIZE, lc->iobuf);
}

/* Write the latest COW metadata block */
static int write_metadata(struct snapshot_c *lc)
{
	int i;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);

	printk(KERN_INFO "PJC: writing metadata entry at sector %ld\n", lc->current_metadata_sector);

	/* TODO: May need to allocate pages for this so we don't destroy any read data
	   that need to be written to the other snapshots.
	   ...depends on the ordering of writes... */


	/* Copy the data from the local block to the iobuf pages */
	for (i=0; i < blocksize/SECTOR_SIZE; i++) {
		memcpy(page_address(lc->iobuf->maplist[i]), lc->disk_cow+(SECTOR_SIZE*i), SECTOR_SIZE);
	}

	return write_blocks(lc, lc->current_metadata_sector, blocksize/SECTOR_SIZE, lc->iobuf);
}

/*
 * Construct a snapshot mapping: <origin_dev> <COW-dev> <p/n> <chunk-size> <extent-size>
 */
static int snapshot_ctr(struct dm_table *t, offset_t b, offset_t l,
			int argc, char **argv, void **context)
{
	struct snapshot_c *lc;
	long chunk_size;
	long extent_size;
	int r = -EINVAL;
	char *persistent;
	char *origin_path;
	char *cow_path;


	if (argc < 5) {
		*context = "dm-stripe: Not enough arguments";
		return -EINVAL;
	}

	origin_path = argv[0];
	cow_path = argv[1];

	persistent = argv[2];

	*context = "Persistent flag is not P or N";
	if ((*persistent & 0x5f) != 'P' &&
	    (*persistent & 0x5f) != 'N')
		goto bad;

	chunk_size = simple_strtoul(argv[3], NULL, 10);
	if (chunk_size == 0) {
		*context = "Invalid chunk size";
		goto bad;
	}

	extent_size = simple_strtoul(argv[4], NULL, 10);
	if (chunk_size == 0) {
		*context = "Invalid extent size";
		goto bad;
	}

	*context = "Cannot allocate snapshot context private structure";
	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL)
		goto bad;

	*context = "Cannot get origin device";
	r = dm_table_get_device(t, origin_path, 0, l, &lc->origin_dev);
	if (r)
		goto bad_free;

	*context = "Cannot get COW device";
	r = dm_table_get_device(t, cow_path, 0, l, &lc->cow_dev);
	if (r)
		goto bad_free;

	lc->chunk_size = chunk_size;
	lc->extent_size = extent_size;
	lc->next_free_sector = 0L;
	lc->need_cow  = 0;
	lc->full      = 0;

	/* Allocate hash table for COW data */
	r = -ENOMEM;
	*context = "Unable to allocate has table space";
	if (alloc_hash_table(lc) == -1)
		goto bad_free;

	/* Allocate and set up iobuf */
	*context = "Unable to allocate I/O buffer space";
	if (alloc_kiovec(1, &lc->iobuf))
		goto bad_free1;

	if (alloc_iobuf_pages(lc->iobuf))
		goto bad_free2;

	/* Check the persistent flag - done here because we need the iobuf
	   to check the LV header */
	if ((*persistent & 0x5f) == 'P') {
		lc->persistent = 1;
	}
	else {
		lc->persistent = 0;
	}

	/* For a persistent snapshot allocate some space for the on-disk COW table buffer */
	lc->disk_cow = NULL;
	if (lc->persistent) {
		int blocksize = get_hardsect_size(lc->cow_dev->dev);
		lc->disk_cow = kmalloc(blocksize, GFP_KERNEL);
		if (lc->disk_cow == NULL)
			goto bad_free3;

		memset(lc->disk_cow, 0, blocksize);
		lc->highest_metadata_entry = blocksize/sizeof(struct disk_exception);

		/* Make room for the header and make sure it's hard sector aligned */
		lc->next_free_sector = blocksize/SECTOR_SIZE;

		/* Check for a header on disk and create a new one if not */
		if (read_header(lc) != 0) {
			/* Write a new header */
			lc->start_of_exceptions = lc->next_free_sector;
			lc->next_free_sector += blocksize/SECTOR_SIZE;
			lc->current_metadata_sector = lc->start_of_exceptions;
			lc->current_metadata_entry = 1; /* 0th entry is the onward pointer */

			if (write_header(lc) != 0) {
				printk(KERN_WARNING "Error writing header to snapshot volume %x\n",
				       lc->cow_dev->dev);
				goto bad_free4;
			}
			if (write_metadata(lc) != 0) {
				printk(KERN_WARNING "Error writing initial COW table to snapshot volume %x\n",
				       lc->cow_dev->dev);
				goto bad_free4;
			}
		}
	}

        /* Add snapshot to the list of snapshots for this origin */
	r = -EINVAL;
	*context = "Cannot register snapshot origin";
	if (!register_snapshot(lc->origin_dev->dev, lc))
	    goto bad_free4;

	*context = lc;
	return 0;

 bad_free4:
	if (lc->disk_cow)
		kfree(lc->disk_cow);
 bad_free3:
	unmap_kiobuf(lc->iobuf);
 bad_free2:
	free_kiovec(1, &lc->iobuf);
 bad_free1:
	vfree(lc->hash_table);
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
	vfree(lc->hash_table);

	dm_table_put_device(t, lc->origin_dev);
	dm_table_put_device(t, lc->cow_dev);
	kfree(c);
}

static int snapshot_map(struct buffer_head *bh, int rw, void *context)
{
	struct exception *ex;
	struct snapshot_c *lc = (struct snapshot_c *) context;

	/* Full snapshots are not usable */
	if (lc->full)
		return -1;

	/* By default reads come from the origin */
	bh->b_rdev = lc->origin_dev->dev;

	/* Unless it has been remapped */
	ex = find_exception(context, bh->b_rsector);
	if (ex) {
		printk(KERN_INFO "PJC: snapshot_map: chunk_size = %d, Osector= %ld, Rsector = %d+%ld\n", lc->chunk_size, bh->b_rsector, ex->rsector_new, bh->b_rsector%lc->chunk_size);

		bh->b_rdev = lc->cow_dev->dev;
		bh->b_rsector = ex->rsector_new + bh->b_rsector%lc->chunk_size;
	}

	/* Write to snapshot - higher level takes care of RW/RO flags so we should only
	   get this if we are writeable */
	if (rw == WRITE) {

		/* Block is already remapped - use that */
		if (ex) {
			printk(KERN_INFO "PJC: snapshot_map: WRITE chunk_size = %d, Osector= %ld, Rsector = %d+%ld\n", lc->chunk_size, bh->b_rsector, ex->rsector_new, bh->b_rsector%lc->chunk_size);
			bh->b_rdev = lc->cow_dev->dev;
			bh->b_rsector = ex->rsector_new + bh->b_rsector%lc->chunk_size;
		}
		else {
		/* TODO: Remap block for writing, should be fairly straightforward,
		   need to move code out of dm_do_snapshot into its own routine and call that */
		}
	}

	return 1;
}

/* Called on a write from the origin driver */
int dm_do_snapshot(struct dm_dev *origin, struct buffer_head *bh)
{
        struct list_head *origin_snaps = (struct list_head *)lookup_snapshot_list(origin->dev);
	struct list_head *snap_list;
	unsigned int max_chunksize = 0;
	int need_cow = 0;
	int max_blksize;
	int min_blksize;

	/* SCARY TODO: Think about cluster locking */

	max_blksize = get_hardsect_size(origin->dev);
	min_blksize = get_hardsect_size(origin->dev);

	if (origin_snaps) {
		list_for_each(snap_list, origin_snaps) {
			struct snapshot_c *snap;
			struct exception *ex;
			snap = list_entry(snap_list, struct snapshot_c, list);

			/* Ignore full snapshots */
			if (snap->full)
				continue;

			/* Check exception table to see if block is already remapped in this
			   snapshot and mark the snapshot as needing a COW if not */
			ex = find_exception(snap, bh->b_rsector);
			if (!ex) {
				int *sizes;
				offset_t dev_size = 0;

				/* Get maxima/minima */
				max_chunksize = max(max_chunksize, snap->chunk_size);
				max_blksize = max(max_blksize, get_hardsect_size(snap->cow_dev->dev));
				min_blksize = min(min_blksize, get_hardsect_size(snap->cow_dev->dev));

                                /* Check for full snapshot. Doing the size calculation here means that
				   the COW device can be resized without telling us */
				if ( (sizes = blk_size[MAJOR(snap->cow_dev->dev)]) )
					dev_size = sizes[MINOR(snap->cow_dev->dev)]<<1;
				if (snap->next_free_sector >= dev_size) {
					        /* Snapshot is full, we can't use it */
						printk(KERN_WARNING "Snapshot %x is full\n", snap->cow_dev->dev);
						snap->full = 1;
						/* Mark it full on the device */
						write_header(snap);

				}
				else {
					snap->need_cow = 1;
					need_cow++;
				}
			}
			else {
				/* Remove this else clause later. But, for now, I like to
				   know what's going on */
//				printk(KERN_INFO "PJC: dm_do_snapshot. block already remapped sector= %ld\n", bh->b_rsector);
			}
		}

		/* At least one snapshot needs a COW */
		if (need_cow) {
			unsigned long read_start;
			unsigned int nr_sectors;
			unsigned int max_sectors;
			struct snapshot_c *read_snap;

			/* Read the original block(s) from origin device */
			read_start = bh->b_rsector - (bh->b_rsector % max_chunksize);
			max_sectors = KIO_MAX_SECTORS * (min_blksize>>9);
			nr_sectors = min(max_chunksize, max_sectors);

			/* We need a snapshot_c for this, just get the first one.
			   All we are really after is the preallocated iobuf */
			read_snap = list_entry(origin_snaps->next, struct snapshot_c, list);
			if (read_blocks(read_snap, read_snap->origin_dev->dev, read_start, nr_sectors)) {
				printk(KERN_INFO "PJC: Read blocks from device %x failed\n", read_snap->origin_dev->dev);
				return -1;
			}

			list_for_each(snap_list, origin_snaps) {
				struct snapshot_c *snap;
				snap = list_entry(snap_list, struct snapshot_c, list);

				/* Update this snapshot if needed */
				if (snap->need_cow) {

					printk(KERN_INFO "PJC: Writing COW orig sector %ld, cow sector %ld, sectors=%d\n",
					       read_start, snap->next_free_sector, nr_sectors);

					/* Write snapshot block */
					if (write_blocks(snap, snap->next_free_sector, nr_sectors, read_snap->iobuf)) {
						printk(KERN_INFO "PJC: Write blocks to %x failed\n", snap->cow_dev->dev);
						continue;
					}

					/* Update exception table */
					if (add_exception(snap, read_start, snap->next_free_sector)) {
						printk(KERN_WARNING "Snapshot %x error adding new exception entry\n", snap->cow_dev->dev);
						/* Error here - treat it as full */
						snap->full = 1;
						write_header(snap);
					}

					snap->next_free_sector += nr_sectors;

					/* Done this one */
					snap->need_cow = 0;
				}
			}
		}
	}
	return 1;
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
		printk(KERN_ERR
		       "Device mapper: Snapshot: register failed %d\n", r);

	return r;
}

static void __exit snapshot_exit(void)
{
	int r = dm_unregister_target(&snapshot_target);

	if (r < 0)
		printk(KERN_ERR
		       "Device mapper: Snapshot: unregister failed %d\n", r);
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
