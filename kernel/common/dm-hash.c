/*
 * Copyright (C) 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

/*
 * We need to be able to quickly return the struct mapped_device,
 * whether it is looked up by name, uuid or by kdev_t.  Note that
 * multiple major numbers are now supported, so we cannot keep
 * things simple by putting them in an array.
 *
 * Instead this will be implemented as a trio of closely coupled
 * hash tables.
 */

#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

#include "dm.h"

struct hash_cell {
	struct list_head list;
	struct mapped_device *md;
};

#define NUM_BUCKETS 64
#define MASK_BUCKETS (NUM_BUCKETS - 1)
#define HASH_MULT 2654435387U
static struct list_head *_dev_buckets;
static struct list_head *_name_buckets;
static struct list_head *_uuid_buckets;

/*
 * Guards access to all three tables.
 */
static DECLARE_RWSEM(_hash_lock);


/*-----------------------------------------------------------------
 * Init/exit code
 *---------------------------------------------------------------*/
void dm_hash_exit(void)
{
	if (_dev_buckets) {
		kfree(_dev_buckets);
		_dev_buckets = NULL;
	}

	if (_name_buckets) {
		kfree(_name_buckets);
		_name_buckets = NULL;
	}

	if (_uuid_buckets) {
		kfree(_uuid_buckets);
		_uuid_buckets = NULL;
	}
}

struct list_head *alloc_buckets(void)
{
	struct list_head *buckets;
	unsigned int i, len;

	len = NUM_BUCKETS * sizeof(struct list_head);
	buckets = kmalloc(len, GFP_KERNEL);
	if (buckets)
		for (i = 0; i < NUM_BUCKETS; i++)
			INIT_LIST_HEAD(buckets + i);

	return buckets;
}

int dm_hash_init(void)
{
	_dev_buckets = alloc_buckets();
	if (!_dev_buckets)
		goto bad;

	_name_buckets = alloc_buckets();
	if (!_name_buckets)
		goto bad;

	_uuid_buckets = alloc_buckets();
	if (!_uuid_buckets)
		goto bad;

	return 0;

      bad:
	dm_hash_exit();
	return -ENOMEM;
}


/*-----------------------------------------------------------------
 * Hash functions
 *---------------------------------------------------------------*/
static inline unsigned int hash_dev(kdev_t dev)
{
	return (HASHDEV(dev) * HASH_MULT) & MASK_BUCKETS;
}

/*
 * We're not really concerned with the str hash function being
 * fast since it's only used by the ioctl interface.
 */
static unsigned int hash_str(const char *str)
{
	unsigned int h = 0;

	while (*str)
		h = (h + (unsigned int) *str++) * HASH_MULT;

	return h & MASK_BUCKETS;
}


/*-----------------------------------------------------------------
 * Code for looking up the device by kdev_t.
 *---------------------------------------------------------------*/
static struct hash_cell *__get_dev_cell(kdev_t dev)
{
	struct list_head *tmp;
	struct hash_cell *hc;
	unsigned int h = hash_dev(dev);

	list_for_each (tmp, _dev_buckets + h) {
		hc = list_entry(tmp, struct hash_cell, list);
		if (kdev_same(hc->md->dev, dev))
			return hc;
	}

	return NULL;
}

struct mapped_device *dm_get_r(kdev_t dev)
{
	struct hash_cell *hc;
	struct mapped_device *md = NULL;

	down_read(&_hash_lock);

	hc = __get_dev_cell(dev);
	if (!hc)
		goto out;

	down_read(&hc->md->lock);
	if (!dm_flag(hc->md, DMF_VALID)) {
		up_read(&hc->md->lock);
		goto out;
	}

	md = hc->md;

      out:
	up_read(&_hash_lock);
	return md;
}

struct mapped_device *dm_get_w(kdev_t dev)
{
	struct hash_cell *hc;
	struct mapped_device *md = NULL;

	down_read(&_hash_lock);

	hc = __get_dev_cell(dev);
	if (!hc)
		goto out;

	down_write(&hc->md->lock);
	if (!dm_flag(hc->md, DMF_VALID)) {
		up_write(&hc->md->lock);
		goto out;
	}

	md = hc->md;

      out:
	up_read(&_hash_lock);
	return md;
}


/*-----------------------------------------------------------------
 * Code for looking up a device by name
 *---------------------------------------------------------------*/
static int namecmp(struct mapped_device *md, const char *str, int uuid)
{
	if (!uuid)
		return strcmp(md->name, str);

	if (!md->uuid)
		return -1;	/* never equal */

	return strcmp(md->uuid, str);
}

static struct hash_cell *__get_str_cell(const char *str, int uuid)
{
	struct list_head *tmp, *buckets;
	struct hash_cell *hc;
	unsigned int h = hash_str(str);

	buckets = uuid ? _uuid_buckets : _name_buckets;
	list_for_each (tmp, buckets + h) {
		hc = list_entry(tmp, struct hash_cell, list);
		if (!namecmp(hc->md, str, uuid))
			return hc;
	}

	return NULL;
}

static inline struct mapped_device *get_name(const char *str, int uuid,
					     int write)
{
	struct hash_cell *hc;
	struct mapped_device *md = NULL;

	down_read(&_hash_lock);

	hc = __get_str_cell(str, uuid);
	if (!hc)
		goto out;

	if (write)
		down_write(&hc->md->lock);
	else
		down_read(&hc->md->lock);

	if (!dm_flag(hc->md, DMF_VALID)) {
		if (write)
			up_write(&hc->md->lock);
		else
			up_read(&hc->md->lock);
		goto out;
	}

	md = hc->md;

      out:
	up_read(&_hash_lock);

	return md;
}

struct mapped_device *dm_get_name_r(const char *name)
{
	return get_name(name, 0, 0);
}

struct mapped_device *dm_get_name_w(const char *name)
{
	return get_name(name, 0, 1);
}

struct mapped_device *dm_get_uuid_r(const char *uuid)
{
	return get_name(uuid, 1, 0);
}

struct mapped_device *dm_get_uuid_w(const char *uuid)
{
	return get_name(uuid, 1, 1);
}

/*-----------------------------------------------------------------
 * Inserting and removing and renaming a device.
 *---------------------------------------------------------------*/
static struct hash_cell *alloc_cell(struct mapped_device *md)
{
	struct hash_cell *hc = kmalloc(sizeof(*hc), GFP_KERNEL);
	if (hc) {
		INIT_LIST_HEAD(&hc->list);
		hc->md = md;
	}

	return hc;
}

/*
 * The kdev_t and uuid of a device can never change once it is
 * initially inserted.
 */
int dm_hash_insert(struct mapped_device *md)
{
	struct hash_cell *dev_cell, *name_cell, *uuid_cell;

	/*
	 * Allocate the new cells.
	 */
	dev_cell = name_cell = uuid_cell = NULL;
	if (!(dev_cell = alloc_cell(md)) ||
	    !(name_cell = alloc_cell(md)) ||
	    !(uuid_cell = alloc_cell(md))) {
		if (uuid_cell)
			kfree(uuid_cell);
		if (name_cell)
			kfree(name_cell);
		if (dev_cell)
			kfree(dev_cell);

		return -ENOMEM;
	}

	/*
	 * Insert the cell into all three hash tables.
	 */
	down_write(&_hash_lock);
	if (__get_dev_cell(md->dev))
		goto bad;

	list_add(&dev_cell->list, _dev_buckets + hash_dev(md->dev));

	if (__get_str_cell(md->name, 0)) {
		list_del(&dev_cell->list);
		goto bad;
	}
	list_add(&name_cell->list, _name_buckets + hash_str(md->name));

	if (md->uuid) {
		if (__get_str_cell(md->uuid, 1)) {
			list_del(&name_cell->list);
			list_del(&dev_cell->list);
			goto bad;
		}
		list_add(&uuid_cell->list, _uuid_buckets + hash_str(md->uuid));
	}
	up_write(&_hash_lock);

	if (!md->uuid)
		kfree(uuid_cell);

	return 0;

 bad:
	up_write(&_hash_lock);
	kfree(uuid_cell);
	kfree(name_cell);
	kfree(dev_cell);
	return -EBUSY;
}

static void dispose_cell(struct hash_cell *hc)
{
	list_del(&hc->list);
	kfree(hc);
}

/*
 * md should already have the write lock and DMF_VALID unset.
 */
void dm_hash_remove(struct mapped_device *md)
{
	struct hash_cell *hc;

	/*
	 * Ensure that anything else waiting for the lock gets it and
	 * promptly releases it because DMF_VALID is no longer set.
	 * Acquiring _hash_lock exclusively prevents anything else
	 * starting a search for an md until our md is completely removed.
	 */
	up_write(&md->lock);
	down_write(&_hash_lock);
	down_write(&md->lock);

	/* remove from the dev hash */
	hc = __get_dev_cell(md->dev);
	if (!hc)
		DMWARN("device doesn't appear to be in the dev hash table.");
	else
		dispose_cell(hc);

	/* remove from the name hash */
	hc = __get_str_cell(md->name, 0);
	if (!hc)
		DMWARN("device doesn't appear to be in the name hash table.");
	else
		dispose_cell(hc);

	/* remove from the uuid hash, if it has a uuid */
	if (md->uuid) {
		hc = __get_str_cell(md->uuid, 1);
		if (!hc)
			DMWARN("device doesn't appear to be in the uuid "
			       "hash table.");
		else
			dispose_cell(hc);
	}

	up_write(&_hash_lock);
}

int dm_hash_rename(const char *old, const char *new)
{
	char *new_name, *old_name;
	struct hash_cell *hc;

	/*
	 * duplicate new.
	 */
	new_name = dm_strdup(new);
	if (!new_name)
		return -ENOMEM;

	down_write(&_hash_lock);

	/*
	 * Is new free ?
	 */
	hc = __get_str_cell(new, 0);
	if (hc) {
		DMWARN("asked to rename to an already existing name %s -> %s",
		       old, new);
		up_write(&_hash_lock);
		return -EBUSY;
	}

	/*
	 * Is there such a device as 'old' ?
	 */
	hc = __get_str_cell(old, 0);
	if (!hc) {
		DMWARN("asked to rename a non existent device %s -> %s",
		       old, new);
		up_write(&_hash_lock);
		return -ENXIO;
	}

	/*
	 * rename and move the name cell.
	 */
	list_del(&hc->list);
	old_name = hc->md->name;
	hc->md->name = new_name;
	list_add(&hc->list, _name_buckets + hash_str(new_name));

	up_write(&_hash_lock);
	kfree(old_name);
	return 0;
}
