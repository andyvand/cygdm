/*
 * dm-origin.c
 *
 * Copyright (C) 2001-2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */


#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>

#include "dm.h"

/*
 * Origin: maps a linear range of a device, with hooks for snapshotting.
 */

/*
 * Construct an origin mapping: <dev_path>
 * The context for an origin is merely a 'struct dm_dev *'
 * pointing to the real device.
 */
static int origin_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	int r;
	struct dm_dev *dev;

	if (argc != 1) {
		*context = "dm-origin: incorrect number of arguments";
		return -EINVAL;
	}

	r = dm_table_get_device(t, argv[0], 0, l, &dev);
	if (r) {
		*context = "Cannot get target device";
		return r;
	}

	*context = dev;

	return 0;
}

static void origin_dtr(struct dm_table *t, void *c)
{
	struct dm_dev *dev = (struct dm_dev *) c;

	dm_table_put_device(t, dev);
}

static int origin_map(struct buffer_head *bh, int rw, void *context)
{
	struct dm_dev *dev = (struct dm_dev *) context;

	bh->b_rdev = dev->dev;

	/* Only tell snapshots if this is a write */
	return (rw == WRITE) ? dm_do_snapshot(dev, bh) : 1;
}

static struct target_type origin_target = {
	name:	"snapshot-origin",
	module:	THIS_MODULE,
	ctr:	origin_ctr,
	dtr:	origin_dtr,
	map:	origin_map,
	err:	NULL
};

int __init dm_origin_init(void)
{
	int r = dm_register_target(&origin_target);

	if (r < 0)
		DMERR("Device mapper: Origin: register failed %d\n", r);

	return r;
}

void dm_origin_exit(void)
{
	int r = dm_unregister_target(&origin_target);

	if (r < 0)
		DMERR("Device mapper: Origin: unregister failed %d\n", r);
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
