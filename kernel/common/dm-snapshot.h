/*
 * dm-snapshot.c
 *
 * Copyright (C) 2001-2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#ifndef DM_SNAPSHOT_H
#define DM_SNAPSHOT_H

#include "dm.h"
#include <linux/blkdev.h>

struct exception_table {
	uint32_t hash_mask;
	struct list_head *table;
};

/*
 * The snapshot code deals with largish chunks of the disk at a
 * time. Typically 64k - 256k.
 */
/* FIXME: can we get away with limiting these to a uint32_t ? */
typedef offset_t chunk_t;

struct dm_snapshot {
	struct rw_semaphore lock;

	struct dm_dev *origin;
	struct dm_dev *cow;

	/* List of snapshots per Origin */
	struct list_head list;

	/* Size of data blocks saved - must be a power of 2 */
	chunk_t chunk_size;
	chunk_t chunk_mask;
	chunk_t chunk_shift;

	/* You can't use a snapshot if this is 0 (e.g. if full) */
	int valid;

	struct exception_table pending;
	struct exception_table complete;

	/* The on disk metadata handler */
	struct exception_store *store;
};

/*
 * An exception is used where an old chunk of data has been
 * replaced by a new one.
 */
struct exception {
	struct list_head hash_list;

	chunk_t old_chunk;
	chunk_t new_chunk;
};

/*
 * Abstraction to handle persistent snapshots.
 */
struct exception_store {

	/*
	 * Destroys this object when you've finished with it.
	 */
	void (*destroy)(struct exception_store *store);

	/*
	 * Read the metadata and populate the snapshot.
	 */
	int (*init)(struct exception_store *store,
		     int blocksize, unsigned long extent_size, void **context);

	/*
	 * Find somewhere to store the next exception.
	 */
	int (*prepare_exception)(struct exception_store *store,
				  struct exception *e);

	/*
	 * Update the metadata with this exception.
	 */
	int (*commit_exception)(struct exception_store *store,
				 struct exception *e);

	/*
	 * The snapshot is invalid, note this in the metadata.
	 */
	void (*drop_snapshot)(struct exception_store *store);

	struct dm_snapshot *snap;
	void *context;
};

/*
 * Constructor and destructor for the default persistent
 * store.
 */
struct exception_store *dm_create_persistent(struct dm_snapshot *s,
					     int blocksize,
					     offset_t extent_size,
					     void **error);

struct exception_store *dm_create_transient(struct dm_snapshot *s,
					    int blocksize, void **error);

/*
 * Return the number of sectors in the device.
 */
static inline offset_t get_dev_size(kdev_t dev)
{
	int *sizes;

	sizes = blk_size[MAJOR(dev)];
	if (sizes)
		return sizes[MINOR(dev)] << 1;

	return 0;
}

static inline chunk_t sector_to_chunk(struct dm_snapshot *s, offset_t sector)
{
	return (sector & ~s->chunk_mask) >> s->chunk_shift;
}

static inline offset_t chunk_to_sector(struct dm_snapshot *s, chunk_t chunk)
{
	return chunk << s->chunk_shift;
}

#endif
