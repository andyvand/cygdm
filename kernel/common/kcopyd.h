/*
 * Copyright (C) 2001 Sistina Software
 *
 * This file is released under the GPL.
 */

#ifndef DM_KCOPYD_H
#define DM_KCOPYD_H

/*
 * Needed for the definition of offset_t.
 */
#include <linux/device-mapper.h>
#include <linux/iobuf.h>

struct kcopyd_region {
	kdev_t dev;
	sector_t sector;
	sector_t count;
};

#define MAX_KCOPYD_PAGES 128

struct kcopyd_job {
	struct list_head list;

	/*
	 * Error state of the job.
	 */
	int err;

	/*
	 * Either READ or WRITE
	 */
	int rw;

	/*
	 * The source or destination for the transfer.
	 */
	struct kcopyd_region disk;

	int nr_pages;
	struct page *pages[MAX_KCOPYD_PAGES];

	/*
	 * Shifts and masks that will be useful when dispatching
	 * each buffer_head.
	 */
	sector_t offset;
	sector_t block_size;
	sector_t block_shift;
	sector_t bpp_shift;	/* blocks per page */
	sector_t bpp_mask;

	/*
	 * nr_blocks is how many buffer heads will have to be
	 * displatched to service this job, nr_requested is how
	 * many have been dispatched and nr_complete is how many
	 * have come back.
	 */
	unsigned int nr_blocks;
	atomic_t nr_requested;
	atomic_t nr_incomplete;

	/*
	 * Set this to ensure you are notified when the job has
	 * completed.  'context' is for callback to use.
	 */
	void (*callback) (struct kcopyd_job * job);
	void *context;
};

/*
 * Low level async io routines.
 */
struct kcopyd_job *kcopyd_alloc_job(void);
void kcopyd_free_job(struct kcopyd_job *job);

int kcopyd_queue_job(struct kcopyd_job *job);

/*
 * Submit a copy job to kcopyd.  This is built on top of the
 * previous three fns.
 */
typedef void (*kcopyd_notify_fn) (int err, void *context);

int kcopyd_copy(struct kcopyd_region *from, struct kcopyd_region *to,
		kcopyd_notify_fn fn, void *context);

int kcopyd_write_pages(struct kcopyd_region *to, int nr_pages,
		       struct page **pages, int offset, kcopyd_notify_fn fn,
		       void *context);

/*
 * We only want kcopyd to reserve resources if someone is
 * actually using it.
 */
void kcopyd_inc_client_count(void);
void kcopyd_dec_client_count(void);

#endif
