/*
 * Copyright (C) 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "kcopyd.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>

/* kcopyd priority of mirror operations */
#define MIRROR_COPY_PRIORITY 5

static kmem_cache_t *bh_cachep;

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
	struct buffer_head *bhstring;
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
		dm_notify(lc);	/* TODO: interface ?? */
	}
	kmem_cache_free(bh_cachep, bh);
}

static void mirror_bh(struct mirror_c *mc, struct buffer_head *bh)
{
	struct buffer_head *dbh = kmem_cache_alloc(bh_cachep, GFP_NOIO);
	if (dbh) {
		*dbh = *bh;
		dbh->b_rdev = mc->todev->dev;
		dbh->b_rsector = bh->b_rsector - mc->from_delta + mc->to_delta;
		dbh->b_end_io = mirror_end_io;
		dbh->b_private = mc;

		generic_make_request(WRITE, dbh);
	} else {
		DMERR("kmem_cache_alloc failed for mirror bh");
		mc->error = 1;
	}
}

/* Called when the copy I/O has finished */
static void copy_callback(copy_cb_reason_t reason, void *context, long arg)
{
	struct mirror_c *lc = (struct mirror_c *) context;
	struct buffer_head *bh;

	if (reason == COPY_CB_FAILED_READ || reason == COPY_CB_FAILED_WRITE) {
		DMERR("Mirror block %s on %s failed, sector %ld",
		      reason == COPY_CB_FAILED_READ ? "read" : "write",
		      reason == COPY_CB_FAILED_READ ?
		      kdevname(lc->fromdev->dev) :
		      kdevname(lc->todev->dev), arg);
		lc->error = 1;
		return;
	}

	if (reason == COPY_CB_COMPLETE) {
		/* Say we've finished */
		dm_notify(lc);	/* TODO: interface ?? */
	}

	if (reason == COPY_CB_PROGRESS) {
		dm_notify(lc);	/* TODO: interface ?? */
	}

	/* Submit, and mirror any pending BHs */
	down_write(&lc->lock);
	lc->got_to = arg;

	bh = lc->bhstring;
	lc->bhstring = NULL;
	up_write(&lc->lock);

	while (bh) {
		struct buffer_head *nextbh = bh->b_reqnext;
		bh->b_reqnext = NULL;
		generic_make_request(WRITE, bh);
		mirror_bh(lc, bh);
		bh = nextbh;
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
	struct kcopyd_region src, dest;

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
	lc->error = 0;
	lc->bhstring = NULL;
	init_rwsem(&lc->lock);
	*context = lc;

	/* Tell kcopyd to do the biz */
	src.dev = lc->fromdev->dev;
	src.sector = offset1;
	src.count = l - offset1;

	dest.dev = lc->todev->dev;
	dest.sector = offset2;
	dest.count = l - offset1;

	if (kcopyd_copy(&src, &dest, priority, 0, copy_callback, lc)) {
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

	bh->b_rdev = lc->fromdev->dev;
	bh->b_rsector = bh->b_rsector + lc->from_delta;

	if (rw == WRITE) {
		down_write(&lc->lock);

		/*
		 * If this area is in flight then save it until it's
		 * commited to the mirror disk and then submit it and
		 * its mirror.
		 */
		if (bh->b_rsector > lc->got_to &&
		    bh->b_rsector <= lc->got_to + KIO_MAX_SECTORS) {
			bh->b_reqnext = lc->bhstring;
			lc->bhstring = bh;
			up_write(&lc->lock);
			return 0;
		}

		/*
		 * If we've already copied this block then duplicate
		 * it to the mirror device
		 */
		if (bh->b_rsector < lc->got_to) {
			/* Schedule copy of I/O to other target */
			mirror_bh(lc, bh);
		}
		up_write(&lc->lock);
	}
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
	int r;

	bh_cachep = kmem_cache_create("dm-mirror",
				      sizeof(struct buffer_head),
				      __alignof__(struct buffer_head),
				      0, NULL, NULL);
	if (!bh_cachep) {
		return -1;
	}

	r = dm_register_target(&mirror_target);
	if (r < 0) {
		DMERR("mirror: register failed %d", r);
		kmem_cache_destroy(bh_cachep);
	}
	return r;
}

void dm_mirror_exit(void)
{
	int r = dm_unregister_target(&mirror_target);

	if (r < 0)
		DMERR("mirror: unregister failed %d", r);

	kmem_cache_destroy(bh_cachep);
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
