/*
 * kcopyd.c
 *
 * Copyright (C) 2002 Sistina Software (UK) Limited.
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

/* Hard sector size used all over the kernel */
#define SECTOR_SIZE 512

/* Number of entries in the free list to start with */
#define INITIAL_FREE_LIST_SIZE 10

/* Structure of work to do in the list */
struct copy_work
{
	unsigned long fromsec;
	unsigned long tosec;
	kdev_t fromdev;
	kdev_t todev;
	unsigned long nr_sectors;
	int  throttle;
	void (*callback)(copy_cb_reason_t, void *, long);
	void *context;
	struct list_head list;
};

static LIST_HEAD(work_list);
static LIST_HEAD(free_list);
static struct task_struct *copy_task = NULL;
static struct rw_semaphore work_list_lock;
static struct rw_semaphore free_list_lock;
static DECLARE_MUTEX(start_lock);
static DECLARE_MUTEX(run_lock);
static DECLARE_WAIT_QUEUE_HEAD(start_waitq);
static DECLARE_WAIT_QUEUE_HEAD(work_waitq);
static DECLARE_WAIT_QUEUE_HEAD(freelist_waitq);
static struct kiobuf *iobuf;
static int thread_exit = 0;
static long last_jiffies = 0;


/* Find a free entry from the free-list */
struct copy_work *get_work_struct(void)
{
	struct copy_work *entry = NULL;

	down_write(&free_list_lock);
	if (!list_empty(&free_list)) {
		entry = list_entry(free_list.next, struct copy_work, list);
		list_del(&entry->list);
	}
	up_write(&free_list_lock);

	/* Nothing on the free-list - try to allocate one without doing IO */
	if (!entry) {
		entry = kmalloc(sizeof(struct copy_work), GFP_NOIO);

		/* Failed...wait for IO to finish */
		while (!entry) {
			DECLARE_WAITQUEUE(wq, current);

			set_task_state(current, TASK_INTERRUPTIBLE);
			add_wait_queue(&freelist_waitq, &wq);

			if (list_empty(&free_list))
				schedule();

			set_task_state(current, TASK_RUNNING);
			remove_wait_queue(&freelist_waitq, &wq);

			/* Try again */
			down_write(&free_list_lock);
			if (!list_empty(&free_list)) {
				entry = list_entry(free_list.next, struct copy_work, list);
				list_del(&entry->list);
			}
			up_write(&free_list_lock);
		}
	}

	return entry;
}

/* Allocate pages for a kiobuf. */
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

/* This is where all the real work happens */
static int copy_kthread(void *unused)
{
	copy_task = current;
	daemonize();
	down(&run_lock);

	strcpy(current->comm, "kcopyd");
	wake_up_interruptible(&start_waitq);

	do {
		DECLARE_WAITQUEUE(wq, current);
		struct task_struct *tsk = current;

		down_write(&work_list_lock);

		while (!list_empty(&work_list)) {

			struct copy_work *work_item = list_entry(work_list.next, struct copy_work, list);
			int done_sps;
			long done_sectors = 0;
			copy_cb_reason_t callback_reason = COPY_CB_COMPLETE;

			list_del(&work_item->list);
			up_write(&work_list_lock);

			while (done_sectors < work_item->nr_sectors) {
				long nr_sectors = min((long)KIO_MAX_SECTORS, (long)work_item->nr_sectors - done_sectors);

				/* Read original blocks */
				if (read_blocks(iobuf, work_item->fromdev, work_item->fromsec + done_sectors, nr_sectors)) {
					DMERR("Read blocks from device %s failed\n", kdevname(work_item->fromdev));

					/* Callback error */
					callback_reason = COPY_CB_FAILED_READ;
					goto done_copy;
				}

				/* Write them out again */
				if (write_blocks(iobuf, work_item->todev, work_item->tosec + done_sectors, nr_sectors)) {
					DMERR("Write blocks to %s failed\n", kdevname(work_item->todev));

					/* Callback error */
					callback_reason = COPY_CB_FAILED_WRITE;
					goto done_copy;
				}
				done_sectors += nr_sectors;

				/* If we have exceeded the throttle value (in sectors/second) then
				   sleep for a while */
				done_sps = nr_sectors*HZ/(jiffies-last_jiffies);
				if (work_item->throttle && done_sps > work_item->throttle && done_sps) {
					long start_jiffies = jiffies;
					do {
						schedule_timeout(done_sps - work_item->throttle * HZ);
					} while (jiffies <= start_jiffies+(done_sps - work_item->throttle * HZ));
				}

				/* Do a progress callback */
				if (work_item->callback && done_sectors < work_item->nr_sectors)
					work_item->callback(COPY_CB_PROGRESS, work_item->context, done_sectors);

			}

		done_copy:
			/* Call the callback */
			if (work_item->callback)
				work_item->callback(callback_reason, work_item->context, done_sectors);

			/* Add it back to the free list and notify anybody waiting for an entry */
			down_write(&free_list_lock);
			list_add(&work_item->list, &free_list);
			up_write(&free_list_lock);
			wake_up_interruptible(&freelist_waitq);

			/* Get the work lock again for the top of the while loop */
			down_write(&work_list_lock);
		}
		up_write(&work_list_lock);

		/* Wait for more work */
		set_task_state(tsk, TASK_INTERRUPTIBLE);
		add_wait_queue(&work_waitq, &wq);

		if (list_empty(&work_list))
			schedule();

		set_task_state(tsk, TASK_RUNNING);
		remove_wait_queue(&work_waitq, &wq);

	} while (thread_exit == 0);

	unmap_kiobuf(iobuf);
	free_kiovec(1, &iobuf);

	up(&run_lock);
	return 0;
}

/* API entry point */
int dm_blockcopy(unsigned long fromsec, unsigned long tosec, unsigned long nr_sectors,
		 kdev_t fromdev, kdev_t todev,
		 int throttle, void (*callback)(copy_cb_reason_t, void *, long), void *context)
{
	struct copy_work *newwork;
	static pid_t thread_pid = 0;
	long from_blocksize = get_hardsect_size(fromdev);
	long to_blocksize = get_hardsect_size(todev);

	/* Make sure the start sectors are on physical block boundaries */
	if (fromsec % (from_blocksize/SECTOR_SIZE))
		return -EINVAL;
	if (tosec % (to_blocksize/SECTOR_SIZE))
		return -EINVAL;

	/* Start the thread if we don't have one already */
	down(&start_lock);
	if (copy_task == NULL) {
		thread_pid = kernel_thread(copy_kthread, NULL, 0);
		if (thread_pid > 0) {

			DECLARE_WAITQUEUE(wq, current);
			struct task_struct *tsk = current;

			DMINFO("Started kcopyd thread\n");

			/* Wait for it to complete it's startup initialisation */
			set_task_state(tsk, TASK_INTERRUPTIBLE);
			add_wait_queue(&start_waitq, &wq);

			schedule();

			set_task_state(tsk, TASK_RUNNING);
			remove_wait_queue(&start_waitq, &wq);
		}
		else {
			DMERR("Failed to start kcopyd thread\n");
			up(&start_lock);
			return -EAGAIN;
		}
	}
	up(&start_lock);

	/* This will wait until one is available */
	newwork = get_work_struct();

	newwork->fromsec    = fromsec;
	newwork->tosec      = tosec;
	newwork->fromdev    = fromdev;
	newwork->todev      = todev;
	newwork->nr_sectors = nr_sectors;
	newwork->throttle   = throttle;
	newwork->callback   = callback;
	newwork->context    = context;

	down_write(&work_list_lock);
	list_add_tail(&newwork->list, &work_list);
	up_write(&work_list_lock);

	wake_up_interruptible(&work_waitq);
	return 0;
}


/* Pre-allocate some structures for the free list */
static int allocate_free_list(void)
{
	int i;
	struct copy_work *newwork;

	for (i=0; i<INITIAL_FREE_LIST_SIZE; i++) {
		newwork = kmalloc(sizeof(struct copy_work), GFP_KERNEL);
		if (!newwork)
			return i;
		list_add(&newwork->list, &free_list);
	}
	return i;
}

static int __init kcopyd_init(void)
{
	init_rwsem(&work_list_lock);
	init_rwsem(&free_list_lock);
	init_MUTEX(&start_lock);
	init_MUTEX(&run_lock);

	if (alloc_kiovec(1, &iobuf)) {
		DMERR("Unable to allocate kiobuf for kcopyd\n");
		return -1;
	}

	if (alloc_iobuf_pages(iobuf, KIO_MAX_SECTORS)) {
		DMERR("Unable to allocate pages for kcopyd\n");
		free_kiovec(1, &iobuf);
		return -1;
	}

	if (allocate_free_list() == 0) {
		unmap_kiobuf(iobuf);
		free_kiovec(1, &iobuf);
		DMERR("Unable to allocate any work structures for the free list\n");
		return -1;
	}

	return 0;
}

static void kcopyd_exit(void)
{
	struct list_head *entry, *temp;

	thread_exit = 1;
	wake_up_interruptible(&work_waitq);

	/* Wait for the thread to finish */
	down(&run_lock);
	up(&run_lock);

	/* Free the free list */
	list_for_each_safe(entry, temp, &free_list) {
		struct copy_work *cw;
		cw = list_entry(entry, struct copy_work, list);
		list_del(&cw->list);
		kfree(cw);
	}
}

/* These are only here until it gets added to dm.c */
module_init(kcopyd_init);
module_exit(kcopyd_exit);

MODULE_AUTHOR("Patrick Caulfield <caulfield@sistina.com>");
MODULE_DESCRIPTION("Device Mapper: Copy thread");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(dm_blockcopy);

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
