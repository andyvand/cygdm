/*
 * Copyright (C) 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>

/* kcopyd priority of mirror operations */
#define MIRROR_COPY_PRIORITY 5

/*
 * Mirror: maps a mirror range of a device.
 */
struct mirror_c {
	struct dm_dev *fromdev;
	struct dm_dev *todev;

	unsigned long from_delta;
	unsigned long to_delta;

	unsigned long frompos;
	unsigned long topos;

	unsigned long got_to;
	struct rw_semaphore lock;
	int error;
};

/* Called when a duplicating I/O has finished */
static void mirror_end_io(struct buffer_head *bh, int uptodate)
{
	struct mirror_c *lc = (struct mirror_c *) bh->b_private;

	/* Flag error if it failed */
	if (!uptodate) {
		DMERR("Mirror copy to %s failed", kdevname(lc->todev->dev));
		lc->error = 1;
		dm_notify(lc); /* TODO: interface ?? */
	}
	kfree(bh);
}


/* Called when the copy I/O has finished */
static void copy_callback(copy_cb_reason_t reason, void *context, long arg)
{
	struct mirror_c *lc = (struct mirror_c *) context;

	if (reason == COPY_CB_PROGRESS) {
		lc->got_to = arg;
		return;
	}

	if (reason == COPY_CB_FAILED_READ ||
	    reason == COPY_CB_FAILED_WRITE) {
		DMERR("Mirror block %s on %s failed, sector %ld", reason==COPY_CB_FAILED_READ?"read":"write",
		      reason==COPY_CB_FAILED_READ?kdevname(lc->fromdev->dev):kdevname(lc->todev->dev), arg);
		lc->error = 1;
	}

	if (reason == COPY_CB_COMPLETE) {
		/* Say we've finished */
		dm_notify(lc); /* TODO: interface ?? */
	}
}

/*
 * Construct a mirror mapping: <dev_path1> <offset> <dev_path2> <offset> <throttle> [<priority>]
 */
static int mirror_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	struct mirror_c *lc;
	unsigned long offset1, offset2;
	char *value;
	int priority = MIRROR_COPY_PRIORITY;
	int throttle;

	if (argc <= 4) {
		*context = "dm-mirror: Not enough arguments";
		return -EINVAL;
	}

	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL) {
		*context = "dm-mirror: Cannot allocate mirror context";
		return -ENOMEM;
	}

	if (dm_table_get_device(t, argv[0], 0, l, &lc->fromdev)) {
		*context = "dm-mirror: Device lookup failed";
		goto bad;
	}

	offset1 = simple_strtoul(argv[1], &value, 10);
	if (value == NULL) {
		*context = "Invalid offset for dev1";
		dm_table_put_device(t, lc->fromdev);
		goto bad;
	}

	if (dm_table_get_device(t, argv[2], 0, l, &lc->todev)) {
		*context = "dm-mirror: Device lookup failed";
		dm_table_put_device(t, lc->fromdev);
		goto bad;
	}

	offset2 = simple_strtoul(argv[3], &value, 10);
	if (value == NULL) {
		*context = "Invalid offset for dev2";
		goto bad_put;
	}

	throttle = simple_strtoul(argv[4], &value, 10);
	if (value == NULL) {
		*context = "Invalid throttle value";
		goto bad_put;
	}

	if (argc > 5) {
		priority = simple_strtoul(argv[5], &value, 10);
		if (value == NULL) {
			*context = "Invalid priority value";
			goto bad_put;
		}
	}

	lc->from_delta = (int) offset1 - (int) b;
	lc->to_delta = (int) offset2 - (int) b;
	lc->frompos = offset1;
	lc->topos = offset2;
	lc->error  = 0;
	init_rwsem(&lc->lock);
	*context = lc;

	/* Tell kcopyd to do the biz */
	if (dm_blockcopy(offset1, offset2,
			 l - offset1,
			 lc->fromdev->dev, lc->todev->dev,
			 priority, 0, copy_callback, lc)) {
		DMERR("block copy call failed");
		dm_table_put_device(t, lc->fromdev);
		dm_table_put_device(t, lc->todev);
		goto bad;
	}
	return 0;

 bad_put:
	dm_table_put_device(t, lc->fromdev);
	dm_table_put_device(t, lc->todev);
 bad:
	kfree(lc);
	return -EINVAL;
}

static void mirror_dtr(struct dm_table *t, void *c)
{
	struct mirror_c *lc = (struct mirror_c *) c;

	dm_table_put_device(t, lc->fromdev);
	dm_table_put_device(t, lc->todev);
	kfree(c);
}

static int mirror_map(struct buffer_head *bh, int rw, void *context)
{
	struct mirror_c *lc = (struct mirror_c *) context;

	down_read(&lc->lock);

	bh->b_rdev = lc->fromdev->dev;
	bh->b_rsector = bh->b_rsector + lc->from_delta;

	/* If we've already copied this block then duplicated it to the mirror device */
	if (rw == WRITE && bh->b_rsector < lc->got_to) {

		/* Schedule copy of I/O to other target */
		/* TODO: kmalloc is naff here */
		struct buffer_head *dbh = kmalloc(sizeof(struct buffer_head), GFP_NOIO);
		if (dbh) {
			*dbh = *bh;
			dbh->b_rdev    = lc->todev->dev;
			dbh->b_rsector = bh->b_rsector - lc->from_delta + lc->to_delta;
			dbh->b_end_io  = mirror_end_io;
			dbh->b_private = lc;

			generic_make_request(WRITE, dbh);
		}
		else {
			DMERR("kmalloc failed for mirror bh");
			lc->error = 1;
		}
	}
	up_read(&lc->lock);
	return 1;
}

static struct target_type mirror_target = {
	name:	"mirror",
	module:	THIS_MODULE,
	ctr:	mirror_ctr,
	dtr:	mirror_dtr,
	map:	mirror_map,
};

int __init dm_mirror_init(void)
{
	int r = dm_register_target(&mirror_target);
	if (r < 0)
		DMERR("mirror: register failed %d", r);

	return r;
}

void dm_mirror_exit(void)
{
	int r = dm_unregister_target(&mirror_target);

	if (r < 0)
		DMERR("mirror: unregister failed %d", r);
}

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
