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
struct origin_c {
	struct dm_dev *target_dev;
};

/*
 * Construct an origin mapping: <dev_path> <offset>
 */
static int origin_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	struct origin_c *lc;
	unsigned int start;
	char *value;
	int r = -EINVAL;
	char *path;

	if (argc < 2) {
		*context = "dm-origin: Not enough arguments";
		return -EINVAL;
	}

	path = argv[0];
	start = simple_strtoul(argv[1], &value, 10);
	if (value == NULL) {
		*context = "Invalid offset";
		goto bad;
	}

	*context = "Cannot allocate origin context private structure";
	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL)
		goto bad;

	*context = "Cannot get target device";
	r = dm_table_get_device(t, path, start, l, &lc->target_dev);
	if (r) {
		kfree(lc);
		goto bad;
	}

	*context = lc;

	return 0;

      bad:
	return r;
}

static void origin_dtr(struct dm_table *t, void *c)
{
	struct origin_c *lc = (struct origin_c *) c;

	dm_table_put_device(t, lc->target_dev);
	kfree(c);
}

static int origin_map(struct buffer_head *bh, int rw, void *context)
{
	struct origin_c *lc = (struct origin_c *) context;

	bh->b_rdev = lc->target_dev->dev;
	bh->b_rsector = bh->b_rsector;

	/* Only tell snapshots if this is a write */
	if (rw != READ && rw != READA) {
	        return dm_do_snapshot(lc->target_dev, bh);
	}

	return 1;
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

MODULE_AUTHOR("Patrick Caulfield <caulfield@sistina.com>");
MODULE_DESCRIPTION("Device Mapper: Snapshot origin driver");
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

