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

/*
TODOs:
- allow chunks bigger than one iovec can handle (& prepare for ksnapd)
- don't allocate extent_size buffer for COW (just need 2 * blocksize)
- Less memory copying to/from iobufs (probably integrated with above)
- remove the PJC printks
- lots of testing
*/


/* Magic for persistent snapshots: "SnAp" - Feeble isn't it. */
#define SNAP_MAGIC 0x70416e53

/* Hard sector size used all over the kernel */
#define SECTOR_SIZE 512

/* The on-disk version of the metadata. Only applicable to
   persistent snapshots.
   There is no backward or forward compatibility implemented, snapshots
   with different disk versions than the kernel will not be usable. It is
   expected that "lvcreate" will blank out the start of the COW device before
   calling the snapshot constructor. */
#define SNAPSHOT_DISK_VERSION 1

/* Metadata format: (please keep this up-to-date!)
   Persistent snapshots have a 1 block header (see below for structure) at the
   very start of the device. The COW metadata starts at .start_of_exceptions.

   COW metadata is stored in blocks that are "extent-size" sectors long as an
   array of disk_exception structures in Little-Endian format.
   The last entry in this array has rsector_new set to 0 (this cannot be a legal
   redirection as the header is here) and if rsector_org has a value it is the
   sector number of the next COW metadata sector on the disk. if rsector_org is
   also zero then this is the end of te COW metadata.

   Non-persistent snapshots simple have redirected blocks stored (in chunk_size
   sectors) from hard block 1 to avoid inadvertantly creating a bad header.
*/

/*
 * Internal snapshot structure
 */
struct snapshot_c {
	struct dm_dev *origin_dev;     /* Original device (s/b a snapshot-origin) */
	struct dm_dev *cow_dev;        /* Device holding COW data */
        struct list_head list;         /* List of snapshots per Origin */
	unsigned int chunk_size;       /* Size of data blocks saved */
        long   extent_size;            /* Size of extents used for COW blocks */
	int    full;                   /* 1 if snapshot is full (and therefore unusable) */
	int    persistent;             /* 1 if snapshot is is persistent (save metadata to disk) */
	unsigned long next_free_sector; /* Number of the next free sector for COW/data */
	unsigned long start_of_exceptions;    /* Where the metadata starts */
	unsigned long current_metadata_sector;/* Where we are currently writing the metadata */
	int    current_metadata_entry; /* Pointer into disk_cow array */
	int    highest_metadata_entry; /* Number of metadata entries in the disk_cow array */
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
};

/* An array of these is held in each disk block */
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

/* Size of the hash table for origin volumes. If we make this
   the size of the minors list then it should be nearly perfect */
#define ORIGIN_HASH_SIZE 256

/* Hash table mapping origin volumes to lists of snapshots */
static struct list_head *snapshot_origins = NULL;

/* One of these per registered origin, held in the snapshot_origins hash */
struct origin_list
{
	kdev_t              origin_dev; /* The origin device */
	struct rw_semaphore lock;       /* To serialise access to the metadata */
	struct list_head    list;       /* List pointers for this list */
	struct list_head    snap_list;  /* List of snapshots for this origin */
};

/* Return the list of snapshots for a given origin device */
static struct list_head *lookup_snapshot_list(kdev_t origin, struct origin_list **ret_ol)
{
        struct list_head *slist;
	struct list_head *snapshot_list;

	snapshot_list = &snapshot_origins[MINOR(origin) % (ORIGIN_HASH_SIZE-1)];
	list_for_each(slist, snapshot_list) {
		struct origin_list *ol;
		ol = list_entry(slist, struct origin_list, list);

		if (ol->origin_dev == origin) {
			if (ret_ol) *ret_ol = ol;
			return &ol->snap_list;
		}
	}
	return NULL;
}

/* Make a note of the snapshot and it's origin so we can look it up when
   the origin has a write on it */
static int register_snapshot(kdev_t origin_dev, struct snapshot_c *snap)
{
	struct origin_list *ol;
        struct list_head *sl = (struct list_head *)lookup_snapshot_list(origin_dev, &ol);
	if (sl) {
		/* Add snapshot to an existing origin */
		list_add_tail(&snap->list, sl);
	}
	else {
		struct list_head *snapshot_list;

		/* New origin */
		ol = kmalloc(sizeof(*ol), GFP_KERNEL);
		if (!ol) return 0;

		/* Add this snapshot to the origin's list of snapshots */
		INIT_LIST_HEAD(&ol->snap_list);
		list_add_tail(&snap->list, &ol->snap_list);

		/* Initialise the struct */
		ol->origin_dev = origin_dev;
		init_rwsem(&ol->lock);

		/* Add this origin to the list of origins */
		snapshot_list = &snapshot_origins[MINOR(origin_dev) % (ORIGIN_HASH_SIZE-1)];
		list_add_tail(&ol->list, snapshot_list);
	}

	snap->origin = ol;
	return 1;
}

/* Return the exception data for a sector, or NULL if not remapped */
static struct exception *find_exception(struct snapshot_c *sc, uint32_t b_rsector)
{
	struct list_head *l = &sc->hash_table[(b_rsector/sc->chunk_size) & sc->hash_mask];
        struct list_head *slist;

	list_for_each(slist, l) {
		struct exception *et = list_entry(slist, struct exception, list);

		if (et->rsector_org == b_rsector - (b_rsector % sc->chunk_size))
			return et;
	}
	return NULL;
}

/* Allocate the kiobuf. This is the only code nicked from the
   old snapshot driver */
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
	mem /= 100;
	mem *= 2;
	mem /= sizeof(struct list_head);

	return mem;
}

/* Allocate room for a suitable hash table */
static int alloc_hash_table(struct snapshot_c *sc)
{
	int  i;
	int  hash_size;
	unsigned long cow_dev_size;
	unsigned long origin_dev_size = cow_dev_size = 128*sc->chunk_size;
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

	printk(KERN_INFO "PJC: hash size is %d\n", hash_size);

	sc->hash_mask = hash_size-1;
	sc->hash_size = hash_size;
	sc->hash_table = vmalloc(sizeof(struct list_head) * (hash_size));
	if (!sc->hash_table) return -1;

	for (i=0; i<hash_size; i++)
		INIT_LIST_HEAD(sc->hash_table + i);

	return 0;
}


/* Read in a chunk from the origin device */
static int read_blocks(struct snapshot_c *lc, kdev_t dev, unsigned long start, int nr_sectors)
{
	int i, sectors_per_block, nr_blocks;
	unsigned long blocks[KIO_MAX_SECTORS];
	int blocksize = get_hardsect_size(dev);
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
static int write_blocks(struct snapshot_c *lc, unsigned long start, int nr_sectors, struct kiobuf *iobuf)
{
	int i, sectors_per_block, nr_blocks;
	unsigned long blocks[KIO_MAX_SECTORS];
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
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

	list_add(&new_ex->list, l);

	/* Add to the on-disk metadata */
	if (sc->persistent) {
		int i = sc->current_metadata_entry++;
		unsigned long next_md_block = 0;

		/* Update copy of disk COW */
		sc->disk_cow[i].rsector_org = cpu_to_le64(org);
		sc->disk_cow[i].rsector_new = cpu_to_le64(new);

		printk(KERN_INFO "PJC: Writing metadata entry %d\n", i);
		/* Have we filled this block ? */
		if (sc->current_metadata_entry >= sc->highest_metadata_entry-1) {
			/* Fill in pointer to next metadata block */
			next_md_block = sc->next_free_sector + sc->extent_size;
			sc->disk_cow[i+1].rsector_org = cpu_to_le64(next_md_block);
			sc->disk_cow[i+1].rsector_new = 0;
		}

		/* Commit to disk */
		if (write_metadata(sc)) {
			sc->full = 1; /* Failed. don't try again */
			return -1;
		}

		/* Write a new (empty) metadata block */
		if (sc->current_metadata_entry >= sc->highest_metadata_entry-1) {

			printk("PJC: Starting new metadata block (i=%d, highest=%d\n",i, sc->highest_metadata_entry);
			memset(sc->disk_cow, 0, sc->extent_size*SECTOR_SIZE);
			sc->current_metadata_entry = 0;
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
	int nr_sectors = lc->extent_size;
	int nr_pages  = lc->extent_size / (PAGE_SIZE/SECTOR_SIZE);
	unsigned long cur_sector = lc->start_of_exceptions;
	unsigned long last_sector;
	unsigned long first_free_sector = 0;

	/* Clear the persistent flag so that add_exception() doesn't try to rewrite the table
	   while we are populating it and also to make the snapshot non-persistent in case of
	   an error. */
	lc->persistent = 0;
	do
	{
		first_free_sector = max(first_free_sector, cur_sector+lc->extent_size);
		printk("PJC first_free_sector = %ld (cur_sector+extent_size)\n", first_free_sector);
		status = read_blocks(lc, lc->cow_dev->dev, cur_sector, nr_sectors);
		if (status == 0) {
			/* Copy it to the allocated block */
			for (i=0; i<nr_pages; i++) {
				memcpy( ((char *)lc->disk_cow + (i*PAGE_SIZE)),
				       page_address(lc->iobuf->maplist[i]), PAGE_SIZE);
			}

			/* Now populate the hash table from this data */
			for (i=1; i<lc->highest_metadata_entry &&
				     lc->disk_cow[i].rsector_new != 0; i++) {
				add_exception(lc,
					      le64_to_cpu(lc->disk_cow[i].rsector_org),
					      le64_to_cpu(lc->disk_cow[i].rsector_new));
				first_free_sector = max(first_free_sector, (unsigned long)(le64_to_cpu(lc->disk_cow[i].rsector_new)+lc->chunk_size));
				printk("PJC first_free_sector = %ld (disk_cow+chunk_size)\n", first_free_sector);
			}

		}
		else {
			printk(KERN_WARNING "Error reading COW metadata for %s\n", kdevname(lc->cow_dev->dev));
			return -1;
		}
		last_sector = cur_sector;
		cur_sector = le64_to_cpu(lc->disk_cow[i].rsector_org);

	} while (cur_sector != 0);

	lc->persistent = 1;
	lc->current_metadata_sector = last_sector;
	lc->current_metadata_entry = i;
	lc->next_free_sector = first_free_sector;

	printk(KERN_INFO "PJC: Read metadata. next free sector = %ld, metadata sector = %ld, metadata_entry = %d\n", first_free_sector, last_sector, i);
	return 0;
}

/* Read the snapshot volume header, returns 0 only if it read OK and
   it was valid. The snapshot_c struct is filled in. */
static int read_header(struct snapshot_c *lc)
{
	int status;
	struct snap_disk_header *header;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);
	unsigned long devsize;

	status = read_blocks(lc, lc->cow_dev->dev, 0L, blocksize/SECTOR_SIZE);
	if (status != 0) {
		printk(KERN_INFO "PJC: dev %s error reading header\n", kdevname(lc->cow_dev->dev));
		return -1;
	}

	header = (struct snap_disk_header *)page_address(lc->iobuf->maplist[0]);

	/* Check the magic. It's OK if this fails, we just create a new snapshot header
	   and start from scratch */
	if (le32_to_cpu(header->magic) != SNAP_MAGIC) {
		return 1;
	}

	/* Check the version matches */
	if (le32_to_cpu(header->version) != SNAPSHOT_DISK_VERSION) {
		printk(KERN_INFO "Snapshot dev %s version mismatch. Stored: %d, driver: %d\n",
		       kdevname(lc->cow_dev->dev), le32_to_cpu(header->version), SNAPSHOT_DISK_VERSION);
		return -1;
	}

	/* Check the chunk sizes match */
	if (le32_to_cpu(header->chunk_size) != lc->chunk_size) {
		printk(KERN_INFO "Snapshot dev %s chunk size mismatch. Stored: %d, requested: %d\n",
		       kdevname(lc->cow_dev->dev), le32_to_cpu(header->chunk_size), lc->chunk_size);
		return -1;
	}

	/* Check the extent sizes match */
	if (le32_to_cpu(header->extent_size) != lc->extent_size) {
		printk(KERN_INFO "Snapshot dev %s extent size mismatch. Stored: %d, requested: %ld\n",
		       kdevname(lc->cow_dev->dev), le32_to_cpu(header->extent_size), lc->extent_size);
		return -1;
	}

	/* Get the rest of the data */
	lc->start_of_exceptions = le64_to_cpu(header->start_of_exceptions);
	if (header->full) {
		printk(KERN_INFO "Snapshot dev %s is full. It cannot be used\n", kdevname(lc->cow_dev->dev));
		lc->full = 1;
		return -1;
	}

	/* Validate against the size of the volume */
	devsize = get_dev_size(lc->cow_dev->dev);
	if (lc->start_of_exceptions > devsize) {
		printk(KERN_INFO "Snapshot metadata error on %s. start exceptions > device size (%ld > %ld)\n",
		       kdevname(lc->cow_dev->dev), lc->start_of_exceptions, devsize);
		return -1;
	}

	/* Read metadata into the hash table and update pointers */
	return read_metadata(lc);
}

/* Write (or update) the header. The only time we should need to do
   an update is when the snapshot becomes full */
static int write_header(struct snapshot_c *lc)
{
	struct snap_disk_header *header;
	int blocksize = get_hardsect_size(lc->cow_dev->dev);

	header = (struct snap_disk_header *)page_address(lc->cow_iobuf->maplist[0]);

	header->magic = cpu_to_le32(SNAP_MAGIC);
	header->version = cpu_to_le32(SNAPSHOT_DISK_VERSION);
	header->chunk_size = cpu_to_le32(lc->chunk_size);
	header->extent_size = cpu_to_le32(lc->extent_size);
	header->full = cpu_to_le32(lc->full);

	header->start_of_exceptions = cpu_to_le64(lc->start_of_exceptions);

	/* Must write at least a full block */
	return write_blocks(lc, 0, blocksize/SECTOR_SIZE, lc->cow_iobuf);
}

/* Write the latest COW metadata block
   WARNING: this will fail if a hard block is >= PAGE_SIZE */
static int write_metadata(struct snapshot_c *lc)
{
	char *start_addr;
	unsigned long start_sector;
	int  blocksize = get_hardsect_size(lc->cow_dev->dev);
	int  writesize = blocksize/SECTOR_SIZE;
	int  entry = lc->current_metadata_entry-1;
	unsigned int  page, offset, done;

	/* This will go when I do sensible allocation of the COW blocks. */
	if (entry < 0) entry = 0;

	/* Work out which block to write as we don't want to be rewriting the
	   whole extent each time. */
	start_addr  = (char *)&lc->disk_cow[entry] -
		       ((unsigned long)&lc->disk_cow[entry] % blocksize);
	start_sector = lc->current_metadata_sector + (start_addr - (char *)lc->disk_cow) / SECTOR_SIZE;

	printk(KERN_INFO "PJC: writing metadata entry at sector %ld, addr=%p (disk_cow = %p, curr entry=%d (%p)) writesize=%d\n",
	       start_sector, start_addr, lc->disk_cow, entry, &lc->disk_cow[entry], writesize);

	/* Copy the data from the local block to the iobuf page:
	   This shenanigans is to make it work where blocksize > PAGE_SIZE */
	page = 0;
	offset = 0;
	done = 0;
	while (done < blocksize) {
		int bytes = min(blocksize, (int)PAGE_SIZE-offset);
		memcpy(page_address(lc->cow_iobuf->maplist[page])+offset, start_addr, bytes);

		done += bytes;
		offset += bytes;
		if (offset >= PAGE_SIZE) {
			offset = 0;
			page++;
		}
	}

	/* If the cow entry we have just written is at the end of a block then also write the
	   next block too to make sure it is zeroed. This because the metadata reading routine
	   stops at the first zero entry and if this is the last COW entry written we can't
	   guarantee that what follows is cleared */
	if ( ((unsigned long)&lc->disk_cow[entry] % blocksize) + sizeof(struct disk_exception) == blocksize) {
		printk("PJC: Writing additional block at %ld (page=%d, offset=%d)\n", start_sector+writesize, page, offset);
		memset(page_address(lc->cow_iobuf->maplist[page])+offset, 0, sizeof(struct disk_exception));
		writesize += blocksize/SECTOR_SIZE;
	}

	if (write_blocks(lc, start_sector, writesize, lc->cow_iobuf) != 0) {
		printk("Error writing COW block\n");
		return -1;
	}

	return 0;
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
	if (r) {
		dm_table_put_device(t, lc->origin_dev);
		goto bad_free;
	}

	/* Validate the extent and chunk sizes against the device block size */
	blocksize = get_hardsect_size(lc->origin_dev->dev);
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

	if (chunk_size > KIO_MAX_SECTORS) {
		*context = "Extent size is too big";
		goto bad_putdev;
	}

	lc->chunk_size = chunk_size;
	lc->extent_size = extent_size;
	lc->next_free_sector = 0L;
	lc->need_cow  = 0;
	lc->full      = 0;

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

	/* For a persistent snapshot allocate some space for the on-disk COW table buffer */
	lc->disk_cow = NULL;
	if (lc->persistent) {
		int blocksize = get_hardsect_size(lc->cow_dev->dev);
		int cowblocksize = extent_size*SECTOR_SIZE;
		int status;

		*context = "Unable to allocate COW buffer space";
		lc->disk_cow = vmalloc(cowblocksize);
		if (lc->disk_cow == NULL)
			goto bad_free3;

		memset(lc->disk_cow, 0, cowblocksize);
		lc->highest_metadata_entry = cowblocksize / sizeof(struct disk_exception);

		/* Make room for the header and make sure it's hard sector aligned */
		lc->next_free_sector = blocksize/SECTOR_SIZE;

		/* Allocate and set up iobuf for metadata I/O*/
		*context = "Unable to allocate COW iovec";
		if (alloc_kiovec(1, &lc->cow_iobuf))
			goto bad_free3;

		*context = "Unable to allocate COW I/O buffer space";
		if (alloc_iobuf_pages(lc->cow_iobuf, lc->extent_size + blocksize/SECTOR_SIZE)) {
			free_kiovec(1, &lc->cow_iobuf);
			goto bad_free3;
		}

		/* Check for a header on disk and create a new one if not */
		if ( (status = read_header(lc)) == 1) {
			/* Write a new header */
			lc->start_of_exceptions = lc->next_free_sector;
			lc->next_free_sector += lc->extent_size;
			lc->current_metadata_sector = lc->start_of_exceptions;
			lc->current_metadata_entry = 0;

			*context = "Unable to write snapshot header";
			if (write_header(lc) != 0) {
				printk(KERN_WARNING "Error writing header to snapshot volume %s\n",
				       kdevname(lc->cow_dev->dev));
				goto bad_free4;
			}

			/* Write a blank metadata extent to the device */
			if (write_metadata(lc) != 0) {
				printk(KERN_WARNING "Error writing initial COW table to snapshot volume %s\n",
				       kdevname(lc->cow_dev->dev));
				goto bad_free4;
			}
		}

		/* There is a header but it doesn't match - fail
		   so we don't destroy what might be useful data on disk.
		   If the user really wants to use this COW device for a snapshot then the first
		   sector should be zeroed out first */
		if (status == -1) {
			printk(KERN_INFO "The target LV has a snapshot header but it doesn't match the parameters given. Snapshot creation failed\n");
			goto bad_free4;
		}
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
	if (lc->disk_cow)
		vfree(lc->disk_cow);
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

	if (lc->disk_cow)
		vfree(lc->disk_cow);

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

	down_read(&lc->origin->lock);

	/* By default reads come from the origin */
	bh->b_rdev = lc->origin_dev->dev;

	/* Unless it has been remapped */
	ex = find_exception(context, bh->b_rsector);
	if (ex) {
		bh->b_rdev = lc->cow_dev->dev;
		bh->b_rsector = ex->rsector_new + bh->b_rsector%lc->chunk_size;
	}
	up_read(&lc->origin->lock);

	/* Write to snapshot - higher level takes care of RW/RO flags so we should only
	   get this if we are writeable */
	if (rw == WRITE) {

		/* If the block is already remapped - use that, else remap it */
		if (!ex) {
			/* Remap block for writing */
			unsigned long read_start = bh->b_rsector - (bh->b_rsector % lc->chunk_size);
			unsigned long devsize = get_dev_size(lc->cow_dev->dev);

			down_write(&lc->origin->lock);

			/* Check there is enough space */
			if (lc->next_free_sector + lc->chunk_size >= devsize) {
				printk(KERN_WARNING "Snapshot %s is full\n", kdevname(lc->cow_dev->dev));
				lc->full = 1;
				write_header(lc);
				up_write(&lc->origin->lock);
				return -1;
			}

			/* Read original block */
			if (read_blocks(lc, lc->origin_dev->dev, read_start, lc->chunk_size)) {
				printk(KERN_INFO "PJC: Read blocks from device %s failed\n", kdevname(lc->origin_dev->dev));
				up_write(&lc->origin->lock);
				return -1;
			}

			/* Write it to the COW volume */
			if (write_blocks(lc, lc->next_free_sector, lc->chunk_size, lc->iobuf)) {
				printk(KERN_INFO "PJC: Write blocks to %s failed\n", kdevname(lc->cow_dev->dev));
				up_write(&lc->origin->lock);
				return -1;
			}

			/* Update the exception table */
			if (add_exception(lc, read_start, lc->next_free_sector)) {
				printk(KERN_WARNING "Snapshot %s error adding new exception entry\n", kdevname(lc->cow_dev->dev));
				/* Error here - treat it as full */
				lc->full = 1;
				write_header(lc);
				up_write(&lc->origin->lock);
				return -1;
			}

			/* Update the bh bits to the write goes to the newly remapped volume */
			bh->b_rdev = lc->cow_dev->dev;
			bh->b_rsector = lc->next_free_sector + bh->b_rsector%lc->chunk_size;

			/* Advance the free sector pointer */
			lc->next_free_sector += lc->chunk_size;

			up_write(&lc->origin->lock);
		}
	}

	return 1;
}

/* Called on a write from the origin driver */
int dm_do_snapshot(struct dm_dev *origin, struct buffer_head *bh)
{
        struct list_head *origin_snaps = (struct list_head *)lookup_snapshot_list(origin->dev, NULL);
	struct list_head *snap_list;
	unsigned int max_chunksize = 0;
	int need_cow = 0;
	int max_blksize;
	int min_blksize;
	max_blksize = get_hardsect_size(origin->dev);
	min_blksize = get_hardsect_size(origin->dev);

	if (origin_snaps) {
		struct snapshot_c *lock_snap;

		/* Lock the metadata */
		lock_snap = list_entry(origin_snaps->next, struct snapshot_c, list);
		down_write(&lock_snap->origin->lock);

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
				offset_t dev_size;

				/* Get maxima/minima */
				max_chunksize = max(max_chunksize, snap->chunk_size);
				max_blksize = max(max_blksize, get_hardsect_size(snap->cow_dev->dev));
				min_blksize = min(min_blksize, get_hardsect_size(snap->cow_dev->dev));

                                /* Check for full snapshot. Doing the size calculation here means that
				   the COW device can be resized without telling us */
				dev_size = get_dev_size(snap->cow_dev->dev);
				if (snap->next_free_sector + snap->chunk_size >= dev_size) {
					        /* Snapshot is full, we can't use it */
						printk(KERN_WARNING "Snapshot %s is full\n",
						       kdevname(snap->cow_dev->dev));
						snap->full = 1;
						/* Mark it full on the device */
						write_header(snap);
				}
				else {
					snap->need_cow = 1;
					need_cow++;
				}
			}
		}

		/* At least one snapshot needs a COW */
		if (need_cow) {
			unsigned long read_start;
			unsigned int nr_sectors;
			unsigned int max_sectors;
			struct snapshot_c *read_snap = NULL;

			/* Read the original block(s) from origin device */
			read_start = bh->b_rsector - (bh->b_rsector % max_chunksize);
			max_sectors = KIO_MAX_SECTORS * (min_blksize>>9);
			nr_sectors = min(max_chunksize, max_sectors);

			/* We need a snapshot_c for this, and it need to be the largest one
			   so we can get everyone's chunks in it. */
			list_for_each(snap_list, origin_snaps) {
				struct snapshot_c *snap;
				snap = list_entry(snap_list, struct snapshot_c, list);
				if (!read_snap) {
					read_snap = snap;
				}
				else {
					if (snap->chunk_size > read_snap->chunk_size)
						read_snap = snap;
				}
			}

			/* Now do the read */
			if (read_blocks(read_snap, read_snap->origin_dev->dev, read_start, nr_sectors)) {
				printk(KERN_INFO "PJC: Read blocks from device %s failed\n", kdevname(read_snap->origin_dev->dev));
				up_write(&lock_snap->origin->lock);
				return -1;
			}

			list_for_each(snap_list, origin_snaps) {
				struct snapshot_c *snap;
				snap = list_entry(snap_list, struct snapshot_c, list);

				/* Update this snapshot if needed */
				if (snap->need_cow) {

					/* Write snapshot block */
					if (write_blocks(snap, snap->next_free_sector, snap->chunk_size, read_snap->iobuf)) {
						printk(KERN_INFO "PJC: Write blocks to %s failed\n", kdevname(snap->cow_dev->dev));
						continue;
					}

					/* Update exception table */
					if (add_exception(snap, read_start, snap->next_free_sector)) {
						printk(KERN_WARNING "Snapshot %s error adding new exception entry\n", kdevname(snap->cow_dev->dev));
						/* Error here - treat it as full */
						snap->full = 1;
						write_header(snap);
					}

					snap->next_free_sector += snap->chunk_size;

					/* Done this one */
					snap->need_cow = 0;
				}
			}
		}
		up_write(&lock_snap->origin->lock);
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
	else {
		snapshot_origins = kmalloc(ORIGIN_HASH_SIZE * sizeof(struct list_head), GFP_KERNEL);
		if (snapshot_origins == NULL) {
			printk(KERN_ERR "Device mapper: Snapshot: unable to allocate memory\n");
			r = -1;
		}
		else {
			int i;
			for (i=0; i<ORIGIN_HASH_SIZE; i++)
				INIT_LIST_HEAD(snapshot_origins + i);

		}
	}

	return r;
}

static void __exit snapshot_exit(void)
{
	int r = dm_unregister_target(&snapshot_target);

	if (r < 0)
		printk(KERN_ERR
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
