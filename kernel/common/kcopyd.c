/*
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
#include <linux/mempool.h>
#include <asm/atomic.h>

#include "kcopyd.h"

/* FIXME: this is only needed for the DMERR macros */
#include "dm.h"

/*
 * Hard sector size used all over the kernel.
 */
#define SECTOR_SIZE 512
#define SECTOR_SHIFT 9
static int wake_kcopyd(void);

/*-----------------------------------------------------------------
 * We reserve our own pool of preallocated pages that are
 * only used for kcopyd io.
 *---------------------------------------------------------------*/

/*
 * FIXME: This should be configurable.
 */
#define NUM_PAGES 512

static DECLARE_MUTEX(_pages_lock);
static int _num_free_pages;
static struct page *_pages_array[NUM_PAGES];

static __init int init_pages(void)
{
	int i;
	struct page *p;

	for (i = 0; i < NUM_PAGES; i++) {
		p = alloc_page(GFP_KERNEL);
		if (!p)
			goto bad;

		LockPage(p);
		_pages_array[i] = p;
	}

	_num_free_pages = NUM_PAGES;
	return 0;

      bad:
	while (i--)
		__free_page(_pages_array[i]);
	return -ENOMEM;
}

static void exit_pages(void)
{
	int i;
	struct page *p;

	for (i = 0; i < NUM_PAGES; i++) {
		p = _pages_array[i];
		UnlockPage(p);
		__free_page(p);
	}

	_num_free_pages = 0;
}

static int kcopyd_get_pages(int num, struct page **result)
{
	int i;

	down(&_pages_lock);
	if (_num_free_pages < num) {
		up(&_pages_lock);
		return -ENOMEM;
	}

	for (i = 0; i < num; i++) {
		_num_free_pages--;
		result[i] = _pages_array[_num_free_pages];
	}
	up(&_pages_lock);

	return 0;
}

static void kcopyd_free_pages(int num, struct page **result)
{
	int i;

	down(&_pages_lock);
	for (i = 0; i < num; i++)
		_pages_array[_num_free_pages++] = result[i];
	up(&_pages_lock);
}

/*-----------------------------------------------------------------
 * We keep our own private pool of buffer_heads.  These are just
 * held in a list on the b_reqnext field.
 *---------------------------------------------------------------*/

/*
 * Make sure we have enough buffers to always keep the pages
 * occupied.  So we assume the worst case scenario where blocks
 * are the size of a single sector.
 */
#define NUM_BUFFERS NUM_PAGES * (PAGE_SIZE / SECTOR_SIZE)

static spinlock_t _buffer_lock = SPIN_LOCK_UNLOCKED;
static struct buffer_head *_all_buffers;
static struct buffer_head *_free_buffers;

static __init int init_buffers(void)
{
	int i;
	struct buffer_head *buffers;
	size_t s = sizeof(struct buffer_head) * NUM_BUFFERS;

	/*
	 * FIXME: this should be a vmalloc.
	 */
	buffers = vmalloc(s);
	if (!buffers) {
		DMWARN("Couldn't allocate buffer heads.");
		return -ENOMEM;
	}

	memset(buffers, 0, s);
	for (i = 0; i < NUM_BUFFERS; i++) {
		if (i < NUM_BUFFERS - 1)
			buffers[i].b_reqnext = &buffers[i + 1];
		init_waitqueue_head(&buffers[i].b_wait);
		INIT_LIST_HEAD(&buffers[i].b_inode_buffers);
	}

	_all_buffers = _free_buffers = buffers;
	return 0;
}

static void exit_buffers(void)
{
	vfree(_all_buffers);
}

static struct buffer_head *alloc_buffer(void)
{
	struct buffer_head *r;
	int flags;

	spin_lock_irqsave(&_buffer_lock, flags);

	if (!_free_buffers)
		r = NULL;
	else {
		r = _free_buffers;
		_free_buffers = _free_buffers->b_reqnext;
		r->b_reqnext = NULL;
	}

	spin_unlock_irqrestore(&_buffer_lock, flags);

	return r;
}

/*
 * Only called from interrupt context.
 */
static void free_buffer(struct buffer_head *bh)
{
	int flags;

	spin_lock_irqsave(&_buffer_lock, flags);
	bh->b_reqnext = _free_buffers;
	_free_buffers = bh;
	spin_unlock_irqrestore(&_buffer_lock, flags);
}

/*-----------------------------------------------------------------
 * kcopyd_jobs need to be allocated by the *clients* of kcopyd,
 * for this reason we use a mempool to prevent the client from
 * ever having to do io (which could cause a
 * deadlock).
 *---------------------------------------------------------------*/
#define MIN_JOBS NUM_PAGES

static kmem_cache_t *_job_cache = NULL;
static mempool_t *_job_pool = NULL;

/*
 * We maintain three lists of jobs:
 *
 * i)   jobs waiting for pages
 * ii)  jobs that have pages, and are waiting for the io to be issued.
 * iii) jobs that have completed.
 *
 * All three of these are protected by job_lock.
 */

static spinlock_t _job_lock = SPIN_LOCK_UNLOCKED;

static LIST_HEAD(_complete_jobs);
static LIST_HEAD(_io_jobs);
static LIST_HEAD(_pages_jobs);

static __init int init_jobs(void)
{
	INIT_LIST_HEAD(&_complete_jobs);
	INIT_LIST_HEAD(&_io_jobs);
	INIT_LIST_HEAD(&_pages_jobs);

	_job_cache = kmem_cache_create("kcopyd-jobs", sizeof(struct kcopyd_job),
				       __alignof__(struct kcopyd_job),
				       0, NULL, NULL);
	if (!_job_cache)
		return -ENOMEM;

	_job_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
				   mempool_free_slab, _job_cache);
	if (!_job_pool) {
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

	return 0;
}

static void exit_jobs(void)
{
	mempool_destroy(_job_pool);
	kmem_cache_destroy(_job_cache);
}

struct kcopyd_job *kcopyd_alloc_job(void)
{
	struct kcopyd_job *job;

	job = mempool_alloc(_job_pool, GFP_KERNEL);
	if (!job)
		return NULL;

	memset(job, 0, sizeof(*job));
	return job;
}

void kcopyd_free_job(struct kcopyd_job *job)
{
	mempool_free(job, _job_pool);
}

/*
 * Functions to push and pop a job onto the head of a given job
 * list.
 */
static inline struct kcopyd_job *pop(struct list_head *jobs)
{
	struct kcopyd_job *job = NULL;
	int flags;

	spin_lock_irqsave(&_job_lock, flags);

	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct kcopyd_job, list);
		list_del(&job->list);
	}
	spin_unlock_irqrestore(&_job_lock, flags);

	return job;
}

static inline void push(struct list_head *jobs, struct kcopyd_job *job)
{
	int flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}

/*
 * Completion function for one of our buffers.
 */
static void end_bh(struct buffer_head *bh, int uptodate)
{
	struct kcopyd_job *job = bh->b_private;

	mark_buffer_uptodate(bh, uptodate);
	unlock_buffer(bh);

	if (!uptodate)
		job->err = -EIO;

	/* are we the last ? */
	if (atomic_dec_and_test(&job->nr_incomplete)) {
		push(&_complete_jobs, job);
		wake_kcopyd();
	}

	free_buffer(bh);
}

static void dispatch_bh(struct kcopyd_job *job,
			struct buffer_head *bh, int block)
{
	int p;

	/*
	 * Add in the job offset
	 */
	block += job->offset >> job->block_shift;
	bh->b_blocknr = (job->disk.sector >> job->block_shift) + block;

	p = block >> job->bpp_shift;
	block &= job->bpp_mask;

	bh->b_dev = B_FREE;
	bh->b_size = job->block_size;
	set_bh_page(bh, job->pages[p],
		    (block << job->block_shift) << SECTOR_SHIFT);
	bh->b_this_page = bh;

	init_buffer(bh, end_bh, job);

	bh->b_dev = job->disk.dev;
	bh->b_state = ((1 << BH_Mapped) | (1 << BH_Lock) | (1 << BH_Req));

	set_bit(BH_Uptodate, &bh->b_state);
	if (job->rw == WRITE)
		clear_bit(BH_Dirty, &bh->b_state);

	submit_bh(job->rw, bh);
}

/*
 * These three functions process 1 item from the corresponding
 * job list.
 *
 * They return:
 * < 0: error
 *   0: success
 * > 0: can't process yet.
 */
static int run_complete_job(struct kcopyd_job *job)
{
	job->callback(job);
	return 0;
}

/*
 * Request io on as many buffer heads as we can currently get for
 * a particular job.
 */
static int run_io_job(struct kcopyd_job *job)
{
	unsigned int block;
	struct buffer_head *bh;

	for (block = atomic_read(&job->nr_requested);
	     block < job->nr_blocks; block++) {
		bh = alloc_buffer();
		if (!bh)
			break;

		atomic_inc(&job->nr_requested);
		dispatch_bh(job, bh, block);
	}

	return (block == job->nr_blocks) ? 0 : 1;
}

static int run_pages_job(struct kcopyd_job *job)
{
	int r;

	job->nr_pages = (job->disk.count + job->offset) /
	    (PAGE_SIZE / SECTOR_SIZE);
	r = kcopyd_get_pages(job->nr_pages, job->pages);
	if (!r) {
		/* this job is ready for io */
		push(&_io_jobs, job);
		return 0;
	}

	if (r == -ENOMEM)
		/* can complete now */
		return 1;

	return r;
}

/*
 * Run through a list for as long as possible.  Returns the count
 * of successful jobs.
 */
static int process_jobs(struct list_head *jobs, int (*fn) (struct kcopyd_job *))
{
	struct kcopyd_job *job;
	int r, count = 0;

	while ((job = pop(jobs))) {

		r = fn(job);

		if (r < 0) {
			/* error this rogue job */
			job->err = r;
			push(&_complete_jobs, job);
			break;
		}

		if (r > 0) {
			/*
			 * We couldn't service this job ATM, so
			 * push this job back onto the list.
			 */
			push(jobs, job);
			break;
		}

		count++;
	}

	return count;
}

/*
 * kcopyd does this every time it's woken up.
 */
static void do_work(void)
{
	int count;

	/*
	 * We loop round until there is no more work to do.
	 */
	do {
		count = process_jobs(&_complete_jobs, run_complete_job);
		count += process_jobs(&_io_jobs, run_io_job);
		count += process_jobs(&_pages_jobs, run_pages_job);

	} while (count);

	run_task_queue(&tq_disk);
}

/*-----------------------------------------------------------------
 * The daemon
 *---------------------------------------------------------------*/
static struct task_struct *_kcopyd_task;
static atomic_t _kcopyd_must_die;
static DECLARE_MUTEX(_run_lock);
static DECLARE_WAIT_QUEUE_HEAD(_job_queue);

static int kcopyd(void *start_lock)
{
	DECLARE_WAITQUEUE(wq, current);

	daemonize();
	strcpy(current->comm, "kcopyd");
	_kcopyd_task = current;
	atomic_set(&_kcopyd_must_die, 0);
	down(&_run_lock);
	up((struct semaphore *) start_lock);

	add_wait_queue(&_job_queue, &wq);

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);

		if (atomic_read(&_kcopyd_must_die))
			break;

		do_work();
		schedule();
	}

	set_current_state(TASK_RUNNING);
	remove_wait_queue(&_job_queue, &wq);

	up(&_run_lock);
	DMINFO("kcopyd shutting down");
	return 0;
}

static int start_daemon(void)
{
	static pid_t pid = 0;
	DECLARE_MUTEX(start_lock);

	down(&start_lock);
	pid = kernel_thread(kcopyd, &start_lock, 0);
	if (pid <= 0) {
		DMERR("Failed to start kcopyd thread");
		return -EAGAIN;
	}

	/*
	 * wait for the daemon to up this mutex.
	 */
	down(&start_lock);
	DMINFO("Started kcopyd thread");

	return 0;
}

static int stop_daemon(void)
{
	if (_kcopyd_task) {
		atomic_set(&_kcopyd_must_die, 1);
		wake_kcopyd();
		down(&_run_lock);
	}

	return 0;
}

static int wake_kcopyd(void)
{
	int r = 0;

	/* Start the thread if we don't have one already */
	if (!_kcopyd_task)
		r = start_daemon();

	if (!r)
		wake_up_interruptible(&_job_queue);

	return r;
}

static int calc_shift(unsigned int n)
{
	int s;

	for (s = 0; n; s++, n >>= 1)
		;

	return --s;
}

static void calc_block_sizes(struct kcopyd_job *job)
{
	job->block_size = get_hardsect_size(job->disk.dev);
	job->block_shift = calc_shift(job->block_size / SECTOR_SIZE);
	job->bpp_shift = PAGE_SHIFT - job->block_shift - SECTOR_SHIFT;
	job->bpp_mask = (1 << job->bpp_shift) - 1;
	job->nr_blocks = job->disk.count >> job->block_shift;
	atomic_set(&job->nr_requested, 0);
	atomic_set(&job->nr_incomplete, job->nr_blocks);
}

int kcopyd_io(struct kcopyd_job *job)
{
	calc_block_sizes(job);
	push(job->pages[0] ? &_io_jobs : &_pages_jobs, job);
	wake_kcopyd();
	return 0;
}

/*-----------------------------------------------------------------
 * The copier is implemented on top of the simpler async io
 * daemon above.
 *---------------------------------------------------------------*/
struct copy_info {
	kcopyd_notify_fn notify;
	void *notify_context;

	struct kcopyd_region to;
};

#define MIN_INFOS 128
static kmem_cache_t *_copy_cache = NULL;
static mempool_t *_copy_pool = NULL;

static __init int init_copier(void)
{
	_copy_cache = kmem_cache_create("kcopyd-info",
					sizeof(struct copy_info),
					__alignof__(struct copy_info),
					0, NULL, NULL);
	if (!_copy_cache)
		return -ENOMEM;

	_copy_pool = mempool_create(MIN_INFOS, mempool_alloc_slab,
				    mempool_free_slab, _copy_cache);
	if (!_copy_pool) {
		kmem_cache_destroy(_copy_cache);
		return -ENOMEM;
	}

	return 0;
}

static void exit_copier(void)
{
	if (_copy_pool)
		mempool_destroy(_copy_pool);

	if (_copy_cache)
		kmem_cache_destroy(_copy_cache);
}

static inline struct copy_info *alloc_copy_info(void)
{
	return mempool_alloc(_copy_pool, GFP_KERNEL);
}

static inline void free_copy_info(struct copy_info *info)
{
	mempool_free(info, _copy_pool);
}

void copy_complete(struct kcopyd_job *job)
{
	struct copy_info *info = (struct copy_info *) job->context;

	if (info->notify)
		info->notify(job->err, info->notify_context);

	free_copy_info(info);
	kcopyd_free_pages(job->nr_pages, job->pages);
	kcopyd_free_job(job);
}

/*
 * These callback functions implement the state machine that copies regions.
 * FIXME: handle large regions.
 */
void copy_write(struct kcopyd_job *job)
{
	struct copy_info *info = (struct copy_info *) job->context;

	if (job->err && info->notify) {
		info->notify(job->err, job->context);
		kcopyd_free_job(job);
		free_copy_info(info);
		return;
	}

	job->rw = WRITE;
	memcpy(&job->disk, &info->to, sizeof(job->disk));
	job->callback = copy_complete;
	job->context = info;

	/*
	 * Queue the write.
	 */
	kcopyd_io(job);
}

int kcopyd_copy(struct kcopyd_region *from, struct kcopyd_region *to,
		kcopyd_notify_fn fn, void *context)
{
	struct copy_info *info;
	struct kcopyd_job *job;

	/*
	 * Allocate a new copy_info.
	 */
	info = alloc_copy_info();
	if (!info)
		return -ENOMEM;

	job = kcopyd_alloc_job();
	if (!job) {
		free_copy_info(info);
		return -ENOMEM;
	}

	/*
	 * set up for the read.
	 */
	info->notify = fn;
	info->notify_context = context;
	memcpy(&info->to, to, sizeof(*to));

	job->rw = READ;
	memcpy(&job->disk, from, sizeof(*from));

	job->offset = 0;
	calc_block_sizes(job);
	job->callback = copy_write;
	job->context = info;

	/*
	 * Trigger job.
	 */
	kcopyd_io(job);
	return 0;
}

/*-----------------------------------------------------------------
 * Unit setup
 *---------------------------------------------------------------*/
static struct {
	int (*init) (void);
	void (*exit) (void);

} _inits[] = {
#define xx(n) { init_ ## n, exit_ ## n}
	xx(pages),
	xx(buffers),
	xx(jobs),
	xx(copier)
#undef xx
};

static int _has_initialised = 0;

int __init kcopyd_init(void)
{
	const int count = sizeof(_inits) / sizeof(*_inits);

	int r, i;

	if (_has_initialised)
		return 0;

	for (i = 0; i < count; i++) {
		r = _inits[i].init();
		if (r)
			goto bad;
	}

	_has_initialised = 1;
	return 0;

      bad:
	while (i--)
		_inits[i].exit();

	return r;
}

void kcopyd_exit(void)
{
	int i = sizeof(_inits) / sizeof(*_inits);

	if (stop_daemon())
		DMWARN("Couldn't stop kcopyd.");

	while (i--)
		_inits[i].exit();

	_has_initialised = 0;
}
