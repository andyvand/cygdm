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

/*
 * The percentage increment we will wake up users at
 */
#define WAKE_UP_PERCENT 5

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

	unsigned int chunksize;
	unsigned long got_to;
	unsigned long size;
	struct rw_semaphore lock;
	struct buffer_head *bhstring;

	struct dm_table *table;

	int last_percent;

	int error;
};

/* Called when a duplicating I/O has finished */
static void mirror_callback(int err, void *context)
{
	struct mirror_c *lc = (struct mirror_c *) context;

	/* Flag error if it failed */
	if (err) {
		DMERR("Mirror copy to %s failed", kdevname(lc->todev->dev));
		lc->error = 1;
		dm_table_event(lc->table);
	}
}

static void mirror_bh(struct mirror_c *mc, struct buffer_head *bh)
{
	struct kcopyd_region dest;

	dest.dev = mc->todev->dev;
	dest.sector = bh->b_rsector - mc->from_delta + mc->to_delta;
	dest.count = bh->b_size / 512;
	kcopyd_write_pages(&dest, 1, &bh->b_page,
			   ((long) bh->b_data -
			    (long) page_address(bh->b_page)) / 512,
			   mirror_callback, mc);
}

/* Called when the copy I/O has finished */
static void copy_callback(int err, void *context)
{
	struct mirror_c *lc = (struct mirror_c *) context;
	struct buffer_head *bh;

	/* Submit, and mirror any pending BHs */
	down_write(&lc->lock);

	bh = lc->bhstring;
	lc->bhstring = NULL;
	up_write(&lc->lock);

	while (bh) {
		struct buffer_head *nextbh = bh->b_reqnext;
		bh->b_reqnext = NULL;
		mirror_bh(lc, bh);
		generic_make_request(WRITE, bh);
		bh = nextbh;
	}

	if (err) {
		DMERR("Mirror block IO failed");	/* More detail to follow... */
		lc->error = 1;
		return;
	}
	if (lc->got_to + lc->chunksize < lc->size) {
		int pc = (lc->got_to - lc->from_delta) * 100 / lc->size;
		struct kcopyd_region src, dest;

		/* Wake up any listeners if we've reached a milestone percentage */
		if (pc >= lc->last_percent + WAKE_UP_PERCENT) {
			dm_table_event(lc->table);
			lc->last_percent = pc - pc % WAKE_UP_PERCENT;
		}

		/* Do next chunk */
		lc->got_to += lc->chunksize;

		src.dev = lc->fromdev->dev;
		src.sector = lc->frompos + lc->got_to;
		src.count = min((unsigned long) lc->chunksize, 
				lc->size - lc->got_to);

		dest.dev = lc->todev->dev;
		dest.sector = lc->topos + lc->got_to;
		dest.count = src.count;

		if (kcopyd_copy(&src, &dest, copy_callback, lc)) {
			lc->error = 1;
			return;
		}
	} else {
		/* Finished */
		dm_table_event(lc->table);
		lc->got_to = lc->size;
	}
}

/*
 * Construct a mirror mapping: <dev_path1> <offset> <dev_path2> <offset> <chunk-size> [<priority>]
 */
static int mirror_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	struct mirror_c *lc;
	unsigned long offset1, offset2;
	char *value;
	int priority = MIRROR_COPY_PRIORITY;
	int chunksize;
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

	chunksize = simple_strtoul(argv[4], &value, 10);
	if (value == NULL || chunksize == 16) {
		*context = "Invalid chunk size value";
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
	lc->size = l - offset1;
	lc->last_percent = 0;
	lc->got_to = 0;
	lc->chunksize = chunksize;
	lc->table = t;
	init_rwsem(&lc->lock);
	*context = lc;

	/* Tell kcopyd to do the biz */
	src.dev = lc->fromdev->dev;
	src.sector = offset1;
	src.count = min((unsigned long) chunksize, lc->size);

	dest.dev = lc->todev->dev;
	dest.sector = offset2;
	dest.count = src.count;

	kcopyd_inc_client_count();

	if (kcopyd_copy(&src, &dest, copy_callback, lc)) {
		DMERR("block copy call failed");
		dm_table_put_device(t, lc->fromdev);
		dm_table_put_device(t, lc->todev);
		kcopyd_dec_client_count();
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
	kcopyd_dec_client_count();
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
		 * committed to the mirror disk and then submit it and
		 * its mirror.
		 */
		if (bh->b_rsector > lc->got_to &&
		    bh->b_rsector <= lc->got_to + lc->chunksize) {
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
			mirror_bh(lc, bh);
		}
		up_write(&lc->lock);
	}
	return 1;
}

static int mirror_status(status_type_t sts_type, char *result, int maxlen,
			 void *context)
{
	struct mirror_c *mc = (struct mirror_c *) context;

	switch (sts_type) {
	case STATUSTYPE_INFO:
		if (mc->error)
			snprintf(result, maxlen, "Error");
		else
			snprintf(result, maxlen, "%ld%%",
				 (mc->got_to -
				  mc->from_delta) * 100 / mc->size);
		break;

	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %ld %s %ld %d",
			 kdevname(mc->fromdev->dev), mc->frompos,
			 kdevname(mc->todev->dev), mc->topos, mc->chunksize);
		break;
	}
	return 0;
}

static struct target_type mirror_target = {
	name:	"mirror",
	module:	THIS_MODULE,
	ctr:	mirror_ctr,
	dtr:	mirror_dtr,
	map:	mirror_map,
	status:	mirror_status,
};

int __init dm_mirror_init(void)
{
	int r;

	r = dm_register_target(&mirror_target);
	if (r < 0) {
		DMERR("mirror: register failed %d", r);
	}
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
