/*
 * dm-origin.c
 *
 * Copyright (C) 2001 Sistina Software (UK) Limited.
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

/* TODO: put in dm.h */
extern int dm_do_snapshot(struct dm_dev *origin, struct buffer_head *bh);

/*
 * Origin: maps a linear range of a device, with hooks for snapshotting.
 */
struct origin_c {
	struct dm_dev *target_dev;
};

/* A list of origins and their dm-devs so we can translate between them
   when attaching a snapshot */
static LIST_HEAD(origin_devs);
struct origin_dev {
        struct list_head *list;
        struct dm_dev *dev;
        struct origin_c *origin;
};


static inline char *next_token(char **p)
{
	static const char *delim = " \t";
	char *r;

	do {
		r = strsep(p, delim);
	} while (r && *r == 0);

	return r;
}

/*
 * Construct a origin mapping: <dev_path> <offset>
 */
static int origin_ctr(struct dm_table *t, offset_t b, offset_t l,
		      char *args, void **context)
{
	struct origin_c *lc;
	unsigned int start;
	int r = -EINVAL;
	char *tok;
	char *path;
	char *p = args;

	*context = "No device path given";
	path = next_token(&p);
	if (!path)
		goto bad;

	*context = "No initial offset given";
	tok = next_token(&p);
	if (!tok)
		goto bad;
	start = simple_strtoul(tok, NULL, 10);

	*context = "Cannot allocate origin context private structure";
	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL)
		goto bad;

	*context = "Cannot get target device";
	r = dm_table_get_device(t, path, start, l, &lc->target_dev);
	if (r)
		goto bad_free;

	*context = lc;

	return 0;

      bad_free:
	kfree(lc);
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
	        dm_do_snapshot(lc->target_dev, bh);
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

static int __init origin_init(void)
{
	int r = dm_register_target(&origin_target);

	if (r < 0)
		printk(KERN_ERR
		       "Device mapper: Origin: register failed %d\n", r);

	return r;
}

static void __exit origin_exit(void)
{
	int r = dm_unregister_target(&origin_target);

	if (r < 0)
		printk(KERN_ERR
		       "Device mapper: Origin: unregister failed %d\n", r);
}

module_init(origin_init);
module_exit(origin_exit);

MODULE_AUTHOR("Patrick Caulfield <caulfield@sistina.com>");
MODULE_DESCRIPTION("Device Mapper: Snapshot origin driver");
MODULE_LICENSE("GPL")

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
