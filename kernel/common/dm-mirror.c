/*
 * Copyright (C) 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>

/*
 * Mirror: maps a mirror range of a device.
 */
struct mirror_c {
	struct dm_dev *fromdev;
	struct dm_dev *todev;

	unsigned long endsec;
	unsigned long from_delta;
	unsigned long to_delta;

	unsigned long frompos;
	unsigned long topos;
	unsigned long chunk_size;

	struct rw_semaphore lock;
	int error;
};

/* Called when a duplicating I/O has finished */
static void mirror_end_io(struct buffer_head *bh, int uptodate)
{
	struct mirror_c *lc = (struct mirror_c *) bh->b_private;

	/* Flag error if it failed */
	if (!uptodate) {
		DMERR("Mirror copy to %s failed\n", kdevname(lc->todev->dev));
		lc->error = 1;
		dm_notify(lc); /* TODO: interface ?? */
	}
	kfree(bh);
}


/* Called when a chunk I/O has finished - we move onto the next one */
static void copy_callback(int status, void *context)
{
	struct mirror_c *lc = (struct mirror_c *) context;

	if (status != 0) {
		DMERR("Mirror block %s on %s failed\n", status==1?"read":"write",
		      status==1?kdevname(lc->fromdev->dev):kdevname(lc->todev->dev));
		lc->error = 1;
		return;
	}

	down_write(&lc->lock);

	if (lc->frompos < lc->endsec && !lc->error) {
		int chunks = min(lc->chunk_size, lc->endsec - lc->frompos);

		/* Move onto the next block */
		lc->frompos += lc->chunk_size;
		lc->topos += lc->chunk_size;

		if (dm_blockcopy(lc->frompos, lc->topos, chunks, lc->fromdev->dev, lc->todev->dev, 0, copy_callback, lc)) {
			DMERR("Mirror block copy to %s failed\n", kdevname(lc->todev->dev));

			dm_notify(lc); /* TODO: interface ?? */
		}
	}
	else {
		/* Say we've finished */
		dm_notify(lc); /* TODO: interface ?? */
	}
	up_write(&lc->lock);
}

/*
 * Construct a mirror mapping: <dev_path1> <offset> <dev_path2> <offset> <chunk-size>
 */
static int mirror_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	struct mirror_c *lc;
	unsigned int chunk_size;
	unsigned long offset1, offset2;
	char *value;

	if (argc != 5) {
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
		goto bad;
	}

	if (dm_table_get_device(t, argv[2], 0, l, &lc->todev)) {
		*context = "dm-mirror: Device lookup failed";
		goto bad;
	}

	offset2 = simple_strtoul(argv[3], &value, 10);
	if (value == NULL) {
		*context = "Invalid offset for dev2";
		goto bad;
	}

	chunk_size = simple_strtoul(argv[4], &value, 10);
	if (chunk_size == 0 || value == NULL) {
		*context = "Invalid chunk size";
		goto bad;
	}

	lc->from_delta = (int) offset1 - (int) b;
	lc->to_delta = (int) offset2 - (int) b;
	lc->frompos = offset1;
	lc->topos = offset2;
	lc->endsec = l;
	lc->error  = 0;
	lc->chunk_size = chunk_size;
	init_rwsem(&lc->lock);
	*context = lc;

	if (dm_blockcopy(offset1, offset2, chunk_size, lc->fromdev->dev, lc->todev->dev, 0, copy_callback, lc)) {
		DMERR("Initial mirror block copy failed\n");
		dm_table_put_device(t, lc->fromdev);
		dm_table_put_device(t, lc->todev);
		kfree(lc);
		return -EINVAL;
	}
	return 0;

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
	if (rw == WRITE && bh->b_rsector < lc->frompos+lc->chunk_size) {

		/* Schedule copy of I/O to other target */
		/* TODO: kmalloc is naff here */
		struct buffer_head *dbh = kmalloc(sizeof(struct buffer_head), GFP_KERNEL);
		if (dbh) {
			*dbh = *bh;
			dbh->b_rdev    = lc->todev->dev;
			dbh->b_rsector = bh->b_rsector - lc->from_delta + lc->to_delta;
			dbh->b_end_io  = mirror_end_io;
			dbh->b_private = lc;

			generic_make_request(WRITE, dbh);
		}
		else {
			DMERR("kmalloc failed for mirror bh\n");
			lc->error = 1;
			dm_notify(lc); /* TODO: interface ?? */
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

static int __init mirror_init(void)
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


module_init(mirror_init);
module_exit(dm_mirror_exit);

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
