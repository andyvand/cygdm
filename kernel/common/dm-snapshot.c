/*
 * dm-snapshot.c
 *
 * Copyright (C) 2001 Sistina Software (UK) Limited.
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

/* THOUGHT FOR THE DAY:
   bits of this code assume that the snapshot chunk sizes are identical, or at least compatible
   (whatever that means)...do something about it

Other TODOs:
- put some limit on the hashtable size (and figure out why that +1 needs to be there)
- use a hash-table for the list of origin/snaps rather than a list
- deallocate all the memory when we are destroyed and on ctor failure
- writeable snapshots
- optionally non-persisent snapshots.
- test with >1 snapshot
- drop snapshot when it gets full
- save metadata to disk (persistent snapshots)
- check iobuf allocation cos it's probably wrong.

*/



/*
 * Snapshot:
 */
struct snapshot_c {
	struct dm_dev *origin_dev;    /* Original device (s/b a snapshot-origin) */
	struct dm_dev *cow_dev;       /* Device holding COW data */
        struct list_head list;        /* List of snapshots per Origin */
	unsigned int chunk_size;      /* Size of data blocks saved */
        long   extent_size;           /* Size of extents used */
	int    writeable;             /* 1 if snapshot is writeable */
	long   next_free_sector;      /* Number of the next free sector for COW/data */
	struct kiobuf *iobuf;         /* kiobuf for doing I/O to chunks and cows */
	struct list_head *hash_table; /* Hash table for looking up data */
	uint32_t hash_mask;
	int    need_cow;
};

struct exception {
	struct list_head list; /* List of exceptions in this bucket */
	uint32_t rsector_org;
	uint32_t rsector_new;
};


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

	printk("PJC: find_exception: looking for %d, bucket %d\n", b_rsector, (b_rsector/sc->chunk_size) & sc->hash_mask);

	list_for_each(slist, l) {
		struct exception *et = list_entry(slist, struct exception, list);
//		printk("PJC: find_exception: looking for %d(%d), found %d\n", b_rsector, b_rsector - (b_rsector % sc->chunk_size), et->rsector_org);
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

	printk("PJC: hash size is %d\n", hash_size);

	sc->hash_mask = hash_size-1;
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
	for (i = 0; i < nr_pages; i++)
	{
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

static void free_iobuf_pages(struct kiobuf *iobuf)
{
	int bytes, nr_pages, i;

	bytes = (KIO_MAX_SECTORS << (PAGE_SHIFT-9)) * SECTOR_SIZE;
	nr_pages = (bytes + ~PAGE_MASK) >> PAGE_SHIFT;

	for (i = 0; i < nr_pages; i++)	{
		UnlockPage(iobuf->maplist[i]);
		free_page((unsigned long)iobuf->maplist[i]);
	}
}

/*
 * Construct a snapshot mapping: <origin_dev> <COW-dev> <ro/rw> <chunk-size> <extent-size>
 */
static int snapshot_ctr(struct dm_table *t, offset_t b, offset_t l,
			char *args, void **context)
{
	struct snapshot_c *lc;
	long chunk_size;
	long extent_size;
	int r = -EINVAL;
	int  writeable;
	char *tok;
	char *origin_path;
	char *cow_path;
	char *mode;
	char *p = args;

	*context = "No origin device path given";
	origin_path = next_token(&p);
	if (!origin_path)
		goto bad;

	*context = "No COW device path given";
	cow_path = next_token(&p);
	if (!cow_path)
		goto bad;

	*context = "No RO/RW mode given";
	mode = next_token(&p);
	if (!mode)
		goto bad;

	*context = "mode not ro/rw";
	if (strcmp(mode, "ro") != 0 &&
	    strcmp(mode, "rw") != 0)
	    goto bad;

	if (strcmp(mode, "rw") == 0)
		writeable = 1;
	else
		writeable = 0;

	*context = "No chunk size given";
	tok = next_token(&p);
	if (!tok)
		goto bad;
	chunk_size = simple_strtoul(tok, NULL, 10);
	if (chunk_size == 0) {
		*context = "Invalid chunk size";
		goto bad;
	}

	*context = "No extent size given";
	tok = next_token(&p);
	if (!tok)
		goto bad;
	extent_size = simple_strtoul(tok, NULL, 10);

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
	lc->writeable = writeable;
	lc->need_cow  = 0;

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

        /* Add snapshot to the list of snapshots for this origin */
	r = -EINVAL;
	*context = "Cannot register snapshot origin";
	if (!register_snapshot(lc->origin_dev->dev, lc))
	    goto bad_free3;

	*context = lc;
	return 0;

 bad_free3:
	free_iobuf_pages(lc->iobuf);
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

	/* TODO: Deallocate memory used - lots of it. */

	dm_table_put_device(t, lc->origin_dev);
	dm_table_put_device(t, lc->cow_dev);
	kfree(c);
}

static int snapshot_map(struct buffer_head *bh, int rw, void *context)
{
	struct exception *ex;
	struct snapshot_c *lc = (struct snapshot_c *) context;

	/* By default reads come from the origin */
	bh->b_rdev = lc->origin_dev->dev;

	ex = find_exception(context, bh->b_rsector);
	if (ex) {
		printk("PJC: snapshot_map: chunk_size = %d, Osector= %d, Rsector = %d+%d\n", lc->chunk_size, bh->b_rsector, ex->rsector_new, bh->b_rsector%lc->chunk_size);

		bh->b_rdev = lc->cow_dev->dev;
		bh->b_rsector = ex->rsector_new + bh->b_rsector%lc->chunk_size;
	}

	/* Attempt to write to a readonly snapshot */
	if ( (rw == WRITE) &&
	     !lc->writeable) {

		return -1;
	}

	if (rw == WRITE) {
		/* TODO: Remap block for writing, should be fairly straightforward,
		 need to move code out of dm_do_snapshot into its own routine and call that */
	}

	return 1;
}

/* Read in a chunk from the origin device */
static int read_blocks(struct snapshot_c *lc, int start, int nr_sectors)
{
	int i, sectors_per_block, nr_blocks;
	unsigned long blocks[KIO_MAX_SECTORS];
	int blocksize = get_hardsect_size(lc->origin_dev->dev);

	sectors_per_block = blocksize / SECTOR_SIZE;

	/* TODO: do we need this alignment check anymore ?? */
	if (start & (sectors_per_block - 1))
		return 0;

	nr_blocks = nr_sectors / sectors_per_block;
	start /= sectors_per_block;

	for (i = 0; i < nr_blocks; i++)
		blocks[i] = start++;

	lc->iobuf->length = nr_sectors << 9;

	return (brw_kiovec(READ, 1, &lc->iobuf, lc->origin_dev->dev,
			   blocks, blocksize) == nr_sectors << 9);
}

/* Write out the COW blocks */
static int write_blocks(struct snapshot_c *lc, int start, int nr_sectors, struct kiobuf *iobuf)
{
	int i, sectors_per_block, nr_blocks;
	unsigned long blocks[KIO_MAX_SECTORS];
	int blocksize = get_hardsect_size(lc->origin_dev->dev);

	sectors_per_block = blocksize / SECTOR_SIZE;

	nr_blocks = nr_sectors / sectors_per_block;
	start /= sectors_per_block;

	for (i = 0; i < nr_blocks; i++)
		blocks[i] = start++;

	iobuf->length = nr_sectors << 9;

	return (brw_kiovec(WRITE, 1, &iobuf, lc->cow_dev->dev,
			   blocks, blocksize) == nr_sectors<<9);
}

/* Add a new exception to the list */
static int add_exception(struct snapshot_c *sc, unsigned long org, unsigned long new)
{
	struct list_head *l = &sc->hash_table[(org/sc->chunk_size) & sc->hash_mask];
	struct exception *new_ex;

	new_ex = kmalloc(sizeof(struct exception), GFP_KERNEL);
	if (!new_ex) return 0;

	new_ex->rsector_org = org;
	new_ex->rsector_new = new;

	printk("PJC: add_exception: storing %d, bucket %d\n", new_ex->rsector_org, (new_ex->rsector_org/sc->chunk_size) & sc->hash_mask);
	list_add(&new_ex->list, l);

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

                                /* Check for full snapshot. Doing the size calculation here means that the
				   COW device can be resized without telling us */
				if ((sizes = blk_size[MAJOR(snap->cow_dev->dev)]) &&
				    (dev_size = sizes[MINOR(snap->cow_dev->dev)]<<1)) {
					if (snap->next_free_sector > dev_size) {
						/* TODO: Drop snapshot --- full. */
						printk("Snapshot %x is full\n", snap->cow_dev->dev);
					}
				} else {
					snap->need_cow = 1;
					need_cow++;
				}
			}
			else {
				/* Remove this else clause later. But, for now, I like to
				   know what's going on */
				printk("PJC: dm_do_snapshot. block already remapped sector= %d\n", bh->b_rsector);
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
			if (!read_blocks(read_snap, read_start, nr_sectors)) {
				printk("PJC: Read blocks from device %x failed\n", read_snap->origin_dev->dev);
				return -1;
			}

			list_for_each(snap_list, origin_snaps) {
				struct snapshot_c *snap;
				snap = list_entry(snap_list, struct snapshot_c, list);

				/* Update this snapshot if needed */
				if (snap->need_cow) {

					printk("PJC: Writing COW orig sector %d, cow sector %d, sectors=%d\n",
					       read_start, snap->next_free_sector, nr_sectors);

					/* Write snapshot block */
					if (!write_blocks(snap, snap->next_free_sector, nr_sectors, read_snap->iobuf)) {
						printk("PJC: Write blocks to %d failed\n", snap->cow_dev->dev);
						continue;
					}

					/* Update exception table */
					if (!add_exception(snap, read_start, snap->next_free_sector)) {
						// TODO: ERROR
					}

					snap->next_free_sector += nr_sectors;

					/* TODO: Write it to the disk metadata area */

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
