/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/blkdev.h>

/* ceiling(n / size) * size */
static inline unsigned long round_up(unsigned long n, unsigned long size)
{
	unsigned long r = n % size;
	return n + (r ? (size - r) : 0);
}

/* ceiling(n / size) */
static inline unsigned long div_up(unsigned long n, unsigned long size)
{
	return round_up(n, size) / size;
}

/* similar to ceiling(log_size(n)) */
static uint int_log(unsigned long n, unsigned long base)
{
	int result = 0;

	while (n > 1) {
		n = div_up(n, base);
		result++;
	}

	return result;
}

/*
 * return the highest key that you could lookup
 * from the n'th node on level l of the btree.
 */
static offset_t high(struct dm_table *t, int l, int n)
{
	for (; l < t->depth - 1; l++)
		n = get_child(n, CHILDREN_PER_NODE - 1);

	if (n >= t->counts[l])
		return (offset_t) - 1;

	return get_node(t, l, n)[KEYS_PER_NODE - 1];
}

/*
 * fills in a level of the btree based on the
 * highs of the level below it.
 */
static int setup_btree_index(int l, struct dm_table *t)
{
	int n, k;
	offset_t *node;

	for (n = 0; n < t->counts[l]; n++) {
		node = get_node(t, l, n);

		for (k = 0; k < KEYS_PER_NODE; k++)
			node[k] = high(t, l + 1, get_child(n, k));
	}

	return 0;
}

/*
 * highs, and targets are managed as dynamic
 * arrays during a table load.
 */
static int alloc_targets(struct dm_table *t, int num)
{
	offset_t *n_highs;
	struct target *n_targets;
	int n = t->num_targets;

	/*
	 * Allocate both the target array and offset array at once.
	 */
	n_highs = (offset_t *) vcalloc(sizeof(struct target) + sizeof(offset_t),
				       num);
	if (!n_highs)
		return -ENOMEM;

	n_targets = (struct target *) (n_highs + num);

	if (n) {
		memcpy(n_highs, t->highs, sizeof(*n_highs) * n);
		memcpy(n_targets, t->targets, sizeof(*n_targets) * n);
	}

	memset(n_highs + n, -1, sizeof(*n_highs) * (num - n));
	if (t->highs)
		vfree(t->highs);

	t->num_allocated = num;
	t->highs = n_highs;
	t->targets = n_targets;

	return 0;
}

int dm_table_create(struct dm_table **result, int mode)
{
	struct dm_table *t = kmalloc(sizeof(*t), GFP_NOIO);

	if (!t)
		return -ENOMEM;

	memset(t, 0, sizeof(*t));
	INIT_LIST_HEAD(&t->devices);

	/* allocate a single node's worth of targets to begin with */
	if (alloc_targets(t, KEYS_PER_NODE)) {
		kfree(t);
		t = NULL;
		return -ENOMEM;
	}

	init_waitqueue_head(&t->eventq);
	t->mode = mode;
	*result = t;
	return 0;
}

static void free_devices(struct list_head *devices)
{
	struct list_head *tmp, *next;

	for (tmp = devices->next; tmp != devices; tmp = next) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);
		next = tmp->next;
		kfree(dd);
	}
}

void dm_table_destroy(struct dm_table *t)
{
	int i;

	/* destroying the table counts as an event */
	dm_table_event(t);

	/* free the indexes (see dm_table_complete) */
	if (t->depth >= 2)
		vfree(t->index[t->depth - 2]);

	/* free the targets */
	for (i = 0; i < t->num_targets; i++) {
		struct target *tgt = &t->targets[i];

		dm_put_target_type(t->targets[i].type);

		if (tgt->type->dtr)
			tgt->type->dtr(t, tgt->private);
	}

	vfree(t->highs);

	/* free the device list */
	if (t->devices.next != &t->devices) {
		DMWARN("devices still present during destroy: "
		       "dm_table_remove_device calls missing");

		free_devices(&t->devices);
	}

	kfree(t);
}

/*
 * Checks to see if we need to extend highs or targets.
 */
static inline int check_space(struct dm_table *t)
{
	if (t->num_targets >= t->num_allocated)
		return alloc_targets(t, t->num_allocated * 2);

	return 0;
}

/*
 * Convert a device path to a kdev_t.
 */
int lookup_device(const char *path, kdev_t *dev)
{
	int r;
	struct nameidata nd;
	struct inode *inode;

	if (!path_init(path, LOOKUP_FOLLOW, &nd))
		return 0;

	if ((r = path_walk(path, &nd)))
		goto bad;

	inode = nd.dentry->d_inode;
	if (!inode) {
		r = -ENOENT;
		goto bad;
	}

	if (!S_ISBLK(inode->i_mode)) {
		r = -EINVAL;
		goto bad;
	}

	*dev = inode->i_rdev;

      bad:
	path_release(&nd);
	return r;
}

/*
 * See if we've already got a device in the list.
 */
static struct dm_dev *find_device(struct list_head *l, kdev_t dev)
{
	struct list_head *tmp;

	list_for_each(tmp, l) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);
		if (dd->dev == dev)
			return dd;
	}

	return NULL;
}

/*
 * Open a device so we can use it as a map destination.
 */
static int open_dev(struct dm_dev *d)
{
	int err;

	if (d->bd)
		BUG();

	if (!(d->bd = bdget(kdev_t_to_nr(d->dev))))
		return -ENOMEM;

	if ((err = blkdev_get(d->bd, d->mode, 0, BDEV_FILE)))
		return err;

	return 0;
}

/*
 * Close a device that we've been using.
 */
static void close_dev(struct dm_dev *d)
{
	if (!d->bd)
		return;

	blkdev_put(d->bd, BDEV_FILE);
	d->bd = NULL;
}

/*
 * If possible (ie. blk_size[major] is set), this
 * checks an area of a destination device is
 * valid.
 */
static int check_device_area(kdev_t dev, offset_t start, offset_t len)
{
	int *sizes;
	offset_t dev_size;

	if (!(sizes = blk_size[MAJOR(dev)]) || !(dev_size = sizes[MINOR(dev)]))
		/* we don't know the device details,
		 * so give the benefit of the doubt */
		return 1;

	/* convert to 512-byte sectors */
	dev_size <<= 1;

	return ((start < dev_size) && (len <= (dev_size - start)));
}

/*
 * This upgrades the mode on an already open dm_dev.  Being
 * careful to leave things as they were if we fail to reopen the
 * device.
 */
static int upgrade_mode(struct dm_dev *dd, int new_mode)
{
	int r;
	struct dm_dev dd_copy;

	memcpy(&dd_copy, dd, sizeof(dd_copy));

	dd->mode |= new_mode;
	dd->bd = NULL;
	r = open_dev(dd);
	if (!r)
		close_dev(&dd_copy);
	else
		memcpy(dd, &dd_copy, sizeof(dd_copy));

	return r;
}

/*
 * Add a device to the list, or just increment the usage count
 * if it's already present.
 */
int dm_table_get_device(struct dm_table *t, const char *path,
			offset_t start, offset_t len, int mode,
			struct dm_dev **result)
{
	int r;
	kdev_t dev;
	struct dm_dev *dd;
	int major, minor;

	if (sscanf(path, "%x:%x", &major, &minor) == 2) {
		/* Extract the major/minor numbers */
		dev = MKDEV(major, minor);
	} else {
		/* convert the path to a device */
		if ((r = lookup_device(path, &dev)))
			return r;
	}

	dd = find_device(&t->devices, dev);
	if (!dd) {
		dd = kmalloc(sizeof(*dd), GFP_KERNEL);
		if (!dd)
			return -ENOMEM;

		dd->mode = mode;
		dd->dev = dev;
		dd->bd = NULL;

		if ((r = open_dev(dd))) {
			kfree(dd);
			return r;
		}

		atomic_set(&dd->count, 0);
		list_add(&dd->list, &t->devices);

	} else if (dd->mode != (mode | dd->mode)) {
		r = upgrade_mode(dd, mode);
		if (r)
			return r;
	}
	atomic_inc(&dd->count);

	if (!check_device_area(dd->dev, start, len)) {
		DMWARN("device %s too small for target", path);
		dm_table_put_device(t, dd);
		return -EINVAL;
	}

	*result = dd;

	return 0;
}

/*
 * Decrement a devices use count and remove it if neccessary.
 */
void dm_table_put_device(struct dm_table *t, struct dm_dev *dd)
{
	if (atomic_dec_and_test(&dd->count)) {
		close_dev(dd);
		list_del(&dd->list);
		kfree(dd);
	}
}

/*
 * Adds a target to the map
 */
int dm_table_add_target(struct dm_table *t, offset_t highs,
			struct target_type *type, void *private)
{
	int r, n;

	if ((r = check_space(t)))
		return r;

	n = t->num_targets++;
	t->highs[n] = highs;
	t->targets[n].type = type;
	t->targets[n].private = private;

	return 0;
}

static int setup_indexes(struct dm_table *t)
{
	int i, total = 0;
	offset_t *indexes;

	/* allocate the space for *all* the indexes */
	for (i = t->depth - 2; i >= 0; i--) {
		t->counts[i] = div_up(t->counts[i + 1], CHILDREN_PER_NODE);
		total += t->counts[i];
	}

	indexes = (offset_t *) vcalloc(total, (unsigned long) NODE_SIZE);
	if (!indexes)
		return -ENOMEM;

	/* set up internal nodes, bottom-up */
	for (i = t->depth - 2, total = 0; i >= 0; i--) {
		t->index[i] = indexes;
		indexes += (KEYS_PER_NODE * t->counts[i]);
		setup_btree_index(i, t);
	}

	return 0;
}

/*
 * Builds the btree to index the map
 */
int dm_table_complete(struct dm_table *t)
{
	int leaf_nodes, r = 0;

	/* how many indexes will the btree have ? */
	leaf_nodes = div_up(t->num_targets, KEYS_PER_NODE);
	t->depth = 1 + int_log(leaf_nodes, CHILDREN_PER_NODE);

	/* leaf layer has already been set up */
	t->counts[t->depth - 1] = leaf_nodes;
	t->index[t->depth - 1] = t->highs;

	if (t->depth >= 2)
		r = setup_indexes(t);

	return r;
}

void dm_table_event(struct dm_table *t)
{
	wake_up_interruptible(&t->eventq);
}

EXPORT_SYMBOL(dm_table_get_device);
EXPORT_SYMBOL(dm_table_put_device);
EXPORT_SYMBOL(dm_table_event);
