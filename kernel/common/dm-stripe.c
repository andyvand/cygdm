/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>

#include "dm.h"

struct stripe {
	struct dm_dev *dev;
	offset_t physical_start;
};

struct stripe_c {
	offset_t logical_start;
	uint32_t stripes;

	/* The size of this target / num. stripes */
	uint32_t stripe_width;

	/* stripe chunk size */
	uint32_t chunk_shift;
	offset_t chunk_mask;

	struct stripe stripe[0];
};

static inline struct stripe_c *alloc_context(int stripes)
{
	size_t len = sizeof(struct stripe_c) +
	    (sizeof(struct stripe) * stripes);

	return kmalloc(len, GFP_KERNEL);
}

/*
 * Parse a single <dev> <sector> pair
 */
static int get_stripe(struct dm_table *t, struct stripe_c *sc,
		      int stripe, char **argv)
{
	char *end;
	unsigned long start;

	start = simple_strtoul(argv[1], &end, 10);
	if (*end)
		return -EINVAL;

	if (dm_table_get_device(t, argv[0], start, sc->stripe_width,
				&sc->stripe[stripe].dev))
		return -ENXIO;

	sc->stripe[stripe].physical_start = start;
	return 0;
}

/*
 * Construct a striped mapping.
 * <number of stripes> <chunk size (2^^n)> [<dev_path> <offset>]+
 */
static int stripe_ctr(struct dm_table *t, offset_t b, offset_t l,
		      int argc, char **argv, void **context)
{
	struct stripe_c *sc;
	uint32_t stripes;
	uint32_t chunk_size;
	char *end;
	int r, i;

	if (argc < 2) {
		*context = "dm-stripe: Not enough arguments";
		return -EINVAL;
	}

	stripes = simple_strtoul(argv[0], &end, 10);
	if (*end) {
		*context = "dm-stripe: Invalid stripe count";
		return -EINVAL;
	}

	chunk_size =simple_strtoul(argv[1], &end, 10);
	if (*end) {
		*context = "dm-stripe: Invalid chunk_size";
		return -EINVAL;
	}

	if (l % stripes) {
		*context = "dm-stripe: Target length not divisable by "
			   "number of stripes";
		return -EINVAL;
	}

	sc = alloc_context(stripes);
	if (!sc) {
		*context = "dm-stripe: Memory allocation for striped context "
			   "failed";
		return -ENOMEM;
	}

	sc->logical_start = b;
	sc->stripes = stripes;
	sc->stripe_width = l / stripes;

	/*
	 * chunk_size is a power of two
	 */
	if (!chunk_size || (chunk_size & (chunk_size - 1))) {
		*context = "dm-stripe: Invalid chunk size";
		kfree(sc);
		return -EINVAL;
	}

	sc->chunk_mask = chunk_size - 1;
	for (sc->chunk_shift = 0; chunk_size; sc->chunk_shift++)
		chunk_size >>= 1;
	sc->chunk_shift--;

	/*
	 * Get the stripe destinations.
	 */
	for (i = 0; i < stripes; i++) {
		if (argc < 2) {
			*context = "dm-stripe: Not enough destinations "
				   "specified";
			kfree(sc);
			return -EINVAL;
		}

		argv += 2;

		r = get_stripe(t, sc, i, argv);
		if (r < 0) {
			*context = "dm-stripe: Couldn't parse stripe "
				   "destination";
			kfree(sc);
			return r;
		}
	}

	*context = sc;
	return 0;
}

static void stripe_dtr(struct dm_table *t, void *c)
{
	unsigned int i;
	struct stripe_c *sc = (struct stripe_c *) c;

	for (i = 0; i < sc->stripes; i++)
		dm_table_put_device(t, sc->stripe[i].dev);

	kfree(sc);
}

static int stripe_map(struct buffer_head *bh, int rw, void *context)
{
	struct stripe_c *sc = (struct stripe_c *) context;

	offset_t offset = bh->b_rsector - sc->logical_start;
	uint32_t chunk = (uint32_t) (offset >> sc->chunk_shift);
	uint32_t stripe = chunk % sc->stripes;	/* 32bit modulus */
	chunk = chunk / sc->stripes;

	bh->b_rdev = sc->stripe[stripe].dev->dev;
	bh->b_rsector = sc->stripe[stripe].physical_start +
	    (chunk << sc->chunk_shift) + (offset & sc->chunk_mask);
	return 1;
}

static struct target_type stripe_target = {
	name:	"striped",
	module:	THIS_MODULE,
	ctr:	stripe_ctr,
	dtr:	stripe_dtr,
	map:	stripe_map,
};

static int __init stripe_init(void)
{
	int r;

	r = dm_register_target(&stripe_target);
	if (r < 0)
		WARN("linear target register failed");

	return r;
}

static void __exit stripe_exit(void)
{
	if (dm_unregister_target(&stripe_target))
		WARN("striped target unregister failed");

	return;
}

module_init(stripe_init);
module_exit(stripe_exit);

MODULE_AUTHOR("Joe Thornber <thornber@sistina.com>");
MODULE_DESCRIPTION("Device Mapper: Striped mapping");
MODULE_LICENSE("GPL");
