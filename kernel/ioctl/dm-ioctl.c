/*
 * Copyright (C) 2001, 2002 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>
#include <linux/dm-ioctl.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/blk.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#define DM_DRIVER_EMAIL "dm@uk.sistina.com"

/*-----------------------------------------------------------------
 * The ioctl interface needs to be able to look up devices by
 * name or uuid.
 *---------------------------------------------------------------*/
struct hash_cell {
	struct list_head name_list;
	struct list_head uuid_list;

	char *name;
	char *uuid;
	struct mapped_device *md;

	/* I hate devfs */
	devfs_handle_t devfs_entry;
};

#define NUM_BUCKETS 64
#define MASK_BUCKETS (NUM_BUCKETS - 1)
static struct list_head _name_buckets[NUM_BUCKETS];
static struct list_head _uuid_buckets[NUM_BUCKETS];

static devfs_handle_t _dev_dir;
void dm_hash_remove_all(void);

/*
 * Guards access to all three tables.
 */
static DECLARE_RWSEM(_hash_lock);

static void init_buckets(struct list_head *buckets)
{
	unsigned int i;

	for (i = 0; i < NUM_BUCKETS; i++)
		INIT_LIST_HEAD(buckets + i);
}

int dm_hash_init(void)
{
	init_buckets(_name_buckets);
	init_buckets(_uuid_buckets);
	_dev_dir = devfs_mk_dir(0, DM_DIR, NULL);
	return 0;
}

void dm_hash_exit(void)
{
	dm_hash_remove_all();
	devfs_unregister(_dev_dir);
}

/*-----------------------------------------------------------------
 * Hash function:
 * We're not really concerned with the str hash function being
 * fast since it's only used by the ioctl interface.
 *---------------------------------------------------------------*/
static unsigned int hash_str(const char *str)
{
	const unsigned int hash_mult = 2654435387U;
	unsigned int h = 0;

	while (*str)
		h = (h + (unsigned int) *str++) * hash_mult;

	return h & MASK_BUCKETS;
}

/*-----------------------------------------------------------------
 * Code for looking up a device by name
 *---------------------------------------------------------------*/
static struct hash_cell *__get_name_cell(const char *str)
{
	struct list_head *tmp;
	struct hash_cell *hc;
	unsigned int h = hash_str(str);

	list_for_each (tmp, _name_buckets + h) {
		hc = list_entry(tmp, struct hash_cell, name_list);
		if (!strcmp(hc->name, str))
			return hc;
	}

	return NULL;
}

static struct hash_cell *__get_uuid_cell(const char *str)
{
	struct list_head *tmp;
	struct hash_cell *hc;
	unsigned int h = hash_str(str);

	list_for_each (tmp, _uuid_buckets + h) {
		hc = list_entry(tmp, struct hash_cell, uuid_list);
		if (!strcmp(hc->uuid, str))
			return hc;
	}

	return NULL;
}

/*-----------------------------------------------------------------
 * Inserting, removing and renaming a device.
 *---------------------------------------------------------------*/
static inline char *kstrdup(const char *str)
{
	char *r = kmalloc(strlen(str) + 1, GFP_KERNEL);
	if (r)
		strcpy(r, str);
	return r;
}

static struct hash_cell *alloc_cell(const char *name, const char *uuid,
				    struct mapped_device *md)
{
	struct hash_cell *hc;

	hc = kmalloc(sizeof(*hc), GFP_KERNEL);
	if (!hc)
		return NULL;

	hc->name = kstrdup(name);
	if (!hc->name) {
		kfree(hc);
		return NULL;
	}

	if (!uuid)
		hc->uuid = NULL;

	else {
		hc->uuid = kstrdup(uuid);
		if (!hc->uuid) {
			kfree(hc->name);
			kfree(hc);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&hc->name_list);
	INIT_LIST_HEAD(&hc->uuid_list);
	hc->md = md;
	return hc;
}

static void free_cell(struct hash_cell *hc)
{
	if (hc) {
		kfree(hc->name);
		kfree(hc->uuid);
		kfree(hc);
	}
}

/*
 * devfs stuff.
 */
static int register_with_devfs(struct hash_cell *hc)
{
	kdev_t dev = dm_kdev(hc->md);

	hc->devfs_entry =
	    devfs_register(_dev_dir, hc->name, DEVFS_FL_CURRENT_OWNER,
			   major(dev), minor(dev),
			   S_IFBLK | S_IRUSR | S_IWUSR | S_IRGRP,
			   &dm_blk_dops, NULL);

	return 0;
}

static int unregister_with_devfs(struct hash_cell *hc)
{
	devfs_unregister(hc->devfs_entry);
	return 0;
}

/*
 * The kdev_t and uuid of a device can never change once it is
 * initially inserted.
 */
int dm_hash_insert(const char *name, const char *uuid, struct mapped_device *md)
{
	struct hash_cell *cell;

	/*
	 * Allocate the new cells.
	 */
	cell = alloc_cell(name, uuid, md);
	if (!cell)
		return -ENOMEM;

	/*
	 * Insert the cell into all three hash tables.
	 */
	down_write(&_hash_lock);
	if (__get_name_cell(name))
		goto bad;

	list_add(&cell->name_list, _name_buckets + hash_str(name));

	if (uuid) {
		if (__get_uuid_cell(uuid)) {
			list_del(&cell->name_list);
			goto bad;
		}
		list_add(&cell->uuid_list, _uuid_buckets + hash_str(uuid));
	}
	register_with_devfs(cell);
	dm_get(md);
	up_write(&_hash_lock);

	return 0;

      bad:
	up_write(&_hash_lock);
	free_cell(cell);
	return -EBUSY;
}

void __hash_remove(struct hash_cell *hc)
{
	/* remove from the dev hash */
	list_del(&hc->uuid_list);
	list_del(&hc->name_list);
	unregister_with_devfs(hc);
	dm_put(hc->md);
}

void dm_hash_remove_all(void)
{
	int i;
	struct hash_cell *hc;
	struct list_head *tmp, *n;

	down_write(&_hash_lock);
	for (i = 0; i < NUM_BUCKETS; i++) {
		list_for_each_safe (tmp, n, _name_buckets + i) {
			hc = list_entry(tmp, struct hash_cell, name_list);
			__hash_remove(hc);
		}
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
	new_name = kstrdup(new);
	if (!new_name)
		return -ENOMEM;

	down_write(&_hash_lock);

	/*
	 * Is new free ?
	 */
	hc = __get_name_cell(new);
	if (hc) {
		DMWARN("asked to rename to an already existing name %s -> %s",
		       old, new);
		up_write(&_hash_lock);
		return -EBUSY;
	}

	/*
	 * Is there such a device as 'old' ?
	 */
	hc = __get_name_cell(old);
	if (!hc) {
		DMWARN("asked to rename a non existent device %s -> %s",
		       old, new);
		up_write(&_hash_lock);
		return -ENXIO;
	}

	/*
	 * rename and move the name cell.
	 */
	list_del(&hc->name_list);
	old_name = hc->name;
	hc->name = new_name;
	list_add(&hc->name_list, _name_buckets + hash_str(new_name));

	/* rename the device node in devfs */
	unregister_with_devfs(hc);
	register_with_devfs(hc);

	up_write(&_hash_lock);
	kfree(old_name);
	return 0;
}

/*-----------------------------------------------------------------
 * Implementation of the ioctl commands
 *---------------------------------------------------------------*/

struct dm_param {
	struct dm_ioctl *dmi;	/* Followed by data payload */
	void *data_end;		/* Last byte of data */
	size_t output_size;	/* Size of output buffer to return */
};

/*
 * All the ioctl commands get dispatched to functions with this
 * prototype.
 */
typedef int (*ioctl_fn)(struct dm_param *param);

/*
 * Check a string doesn't overrun our buffer.
 */
static int invalid_str(char *str, const void *data_end)
{
	while ((void *) str <= data_end)
		if (!*str++)
			return 0;

	return -EINVAL;
}

/*
 * Locate struct and parameter string for the next target.
 */
static int next_target(struct dm_target_spec *last, uint32_t next,
		       const void *data_end, struct dm_target_spec **spec,
		       char **target_params)
{
	*spec = (struct dm_target_spec *) ((unsigned char *) last + next);
	*target_params = (char *) (*spec + 1);

	if (*spec < (last + 1))
		return -EINVAL;

	return invalid_str(*target_params, data_end);
}

static int populate_table(struct dm_table *table, struct dm_param *param)
{
	int r;
	unsigned int i = 0;
	struct dm_target_spec *spec = (struct dm_target_spec *) param->dmi;
	uint32_t next = param->dmi->data_offset;
	char *target_params;

	if (!param->dmi->target_count) {
		DMWARN("populate_table: no targets specified");
		return -EINVAL;
	}

	for (i = 0; i < param->dmi->target_count; i++) {

		r = next_target(spec, next, param->data_end, &spec,
				&target_params);

		if (r) {
			DMWARN("unable to find target");
			return r;
		}

		r = dm_table_add_target(table, spec->target_type,
					(sector_t) spec->sector_start,
					(sector_t) spec->length, target_params);
		if (r) {
			DMWARN("error adding target to table");
			return -EINVAL;
		}

		next = spec->next;
	}

	return dm_table_complete(table);
}

/*
 * Round up the ptr to an 8-byte boundary.
 */
#define ALIGN_MASK 7
static inline void *align_ptr(void *ptr)
{
	return (void *) (((size_t) (ptr + ALIGN_MASK)) & ~ALIGN_MASK);
}

static inline void *align_data_start(struct dm_param *param)
{
	struct dm_ioctl *dmi = param->dmi;

	dmi->data_offset = align_ptr(dmi + 1) - (void *) dmi;
	return (void *) dmi + dmi->data_offset;
}

/*
 * Copies a dm_ioctl structure and an optional additional payload to
 * userland.
 */
static int results_to_user(struct dm_ioctl *user, struct dm_param *param)
{
	void *data_start;
	struct dm_ioctl *dmi = param->dmi;

	/*
	 * Ensure we never exceed the supplied buffer
	 */
	if (param->output_size > dmi->data_size)
		param->output_size = dmi->data_size;
	else
		dmi->data_size = param->output_size;

	/*
	 * The version number has already been filled in
	 * so we just copy later fields.
	 */
	if (copy_to_user(&user->data_size, &dmi->data_size,
			 sizeof(*dmi) - sizeof(dmi->version)))
		return -EFAULT;

	if (param->output_size <= sizeof(*dmi))
		return 0;

	data_start = (void *) dmi + dmi->data_offset;

	if (copy_to_user((void *) user + dmi->data_offset, data_start,
			 param->output_size - dmi->data_offset))
		return -EFAULT;

	return 0;
}

/*
 * Fills in a dm_ioctl structure, ready for sending back to
 * userland.
 */
static void __info(struct mapped_device *md, struct dm_param *param)
{
	kdev_t dev;
	struct dm_table *table;
	struct block_device *bdev;
	struct dm_ioctl *dmi = param->dmi;

	param->output_size = sizeof(*dmi);

	if (!md) {
		dmi->flags &= ~DM_EXISTS_FLAG;
		return;
	}

	dmi->flags |= DM_EXISTS_FLAG;

	if (dm_suspended(md))
		dmi->flags |= DM_SUSPEND_FLAG;
	else
		dmi->flags &= ~DM_SUSPEND_FLAG;

	dev = dm_kdev(md);
	dmi->dev = kdev_t_to_nr(dev);
	bdev = bdget(dmi->dev);
	dmi->open_count = bdev ? bdev->bd_openers : -1;
	if (bdev)
		bdput(bdev);

	if (is_read_only(dev))
		dmi->flags |= DM_READONLY_FLAG;
	else
		dmi->flags &= ~DM_READONLY_FLAG;

	table = dm_get_table(md);
	dmi->target_count = dm_table_get_num_targets(table);
	dm_table_put(table);
}

/*
 * Always use UUID for lookups if it's present, otherwise use name.
 */

static struct hash_cell *__find_device_hash_cell(struct dm_ioctl *dmi)
{
	struct hash_cell *hc;

	hc = *dmi->uuid ? __get_uuid_cell(dmi->uuid) :
	    __get_name_cell(dmi->name);
	if (hc) {
		/*
		 * Sneakily write in both the name and the uuid
		 * while we have the cell.
		 */
		strncpy(dmi->name, hc->name, sizeof(dmi->name));
		if (hc->uuid)
			strncpy(dmi->uuid, hc->uuid, sizeof(dmi->uuid) - 1);
		else
			dmi->uuid[0] = '\0';
	}

	return hc;
}

static struct mapped_device *find_device(struct dm_ioctl *dmi)
{
	struct hash_cell *hc;
	struct mapped_device *md = NULL;

	down_read(&_hash_lock);
	hc = __find_device_hash_cell(dmi);
	if (hc) {
		md = hc->md;
		dm_get(md);
	}
	up_read(&_hash_lock);

	return md;
}

/*
 * Copies device info back to user space, used by
 * the create and info ioctls.
 */
static int info(struct dm_param *param)
{
	struct mapped_device *md;

	md = find_device(param->dmi);
	__info(md, param);

	if (md)
		dm_put(md);

	return 0;
}

static inline int get_mode(struct dm_ioctl *dmi)
{
	int mode = FMODE_READ | FMODE_WRITE;

	if (dmi->flags & DM_READONLY_FLAG)
		mode = FMODE_READ;

	return mode;
}

static int check_name(const char *name)
{
	if (strchr(name, '/')) {
		DMWARN("invalid device name");
		return -EINVAL;
	}

	return 0;
}

static int create(struct dm_param *param)
{
	int r;
	kdev_t dev = 0;
	struct dm_table *t;
	struct mapped_device *md;
	struct dm_ioctl *dmi = param->dmi;

	r = check_name(dmi->name);
	if (r)
		return r;

	r = dm_table_create(&t, get_mode(dmi));
	if (r)
		return r;

	r = populate_table(t, param);
	if (r) {
		dm_table_put(t);
		return r;
	}

	if (dmi->flags & DM_PERSISTENT_DEV_FLAG)
		dev = to_kdev_t(dmi->dev);

	r = dm_create(dev, t, &md);

	dm_table_put(t);	/* md will have grabbed its own reference */

	if (r)
		return r;

	set_device_ro(dm_kdev(md), (dmi->flags & DM_READONLY_FLAG) ? 1 : 0);

	r = dm_hash_insert(dmi->name, *dmi->uuid ? dmi->uuid : NULL, md);
	if (r) {
		dm_put(md);
		return r;
	}

	__info(md, param);
	dm_put(md);

	return 0;
}

/*
 * Build up the status struct for each target
 */
static void __status(struct mapped_device *md, struct dm_param *param)
{
	unsigned int i, num_targets;
	struct dm_target_spec *spec;
	char *outptr, *data_start;
	status_type_t type;
	struct dm_table *table;
	
	if (!md)
		return;

	table = dm_get_table(md);

	if (param->dmi->flags & DM_STATUS_TABLE_FLAG)
		type = STATUSTYPE_TABLE;
	else
		type = STATUSTYPE_INFO;

	data_start = align_data_start(param);

	outptr = data_start;

	/* Get all the target info */
	num_targets = dm_table_get_num_targets(table);
	for (i = 0; i < num_targets; i++) {
		struct dm_target *ti = dm_table_get_target(table, i);

		/*
		 * Bail out if we would overflow the buffer
		 */
		if ((void *) outptr + sizeof(*spec) + 1 > param->data_end) {
			param->dmi->flags |= DM_BUFFER_FULL_FLAG;
			goto out;
		}

		spec = (struct dm_target_spec *) outptr;

		spec->status = 0;
		spec->sector_start = ti->begin;
		spec->length = ti->len;
		strncpy(spec->target_type, ti->type->name,
			sizeof(spec->target_type));

		outptr += sizeof(*spec);

		/* Get the status/table string from the target driver */
		if (ti->type->status)
			ti->type->status(ti, type, outptr,
					 param->data_end - (void *) outptr + 1);
		else
			outptr[0] = '\0';

		outptr += strlen(outptr) + 1;
		align_ptr(outptr);
		spec->next = (void *) outptr - (void *) data_start;
	}

	param->dmi->flags &= ~DM_BUFFER_FULL_FLAG;

      out:
	param->dmi->target_count = num_targets;
	param->output_size = (void *) outptr - (void *) param->dmi;

	dm_table_put(table);
}

/*
 * Return the status of a device as a text string for each
 * target.
 */
static int get_status(struct dm_param *param)
{
	struct mapped_device *md;

	md = find_device(param->dmi);

	__info(md, param);
	__status(md, param);

	if (md)
		dm_put(md);

	return 0;
}

/*
 * Wait for a device to report an event
 */
static int wait_device_event(struct dm_param *param)
{
	struct mapped_device *md;
	struct dm_table *table;
	DECLARE_WAITQUEUE(wq, current);

	md = find_device(param->dmi);
	if (!md)
		return -ENXIO;

	/*
	 * Wait for a notification event
	 */
	set_current_state(TASK_INTERRUPTIBLE);
	table = dm_get_table(md);
	dm_table_add_wait_queue(table, &wq);
	dm_table_put(table);
	dm_put(md);

	schedule();
	set_current_state(TASK_RUNNING);
	dm_table_remove_wait_queue(table, &wq);

	get_status(param);
	return 0;
}

/*
 * Retrieves a list of devices used by a particular dm device.
 */
static int deps(struct dm_param *param)
{
	struct mapped_device *md;
	struct list_head *tmp;
	struct dm_target_deps *tdeps = NULL;
	struct dm_table *table = NULL;
	void *endpos;

	md = find_device(param->dmi);
	if (!md)
		return -ENXIO;

	__info(md, param);

	table = dm_get_table(md);

	tdeps = align_data_start(param);

	endpos = (void *) tdeps + sizeof(*tdeps);
	if (endpos > param->data_end) {
		param->dmi->flags |= DM_BUFFER_FULL_FLAG;
		goto out;
	}

	/*
	 * Fill in the devices.
	 */
	tdeps->count = 0;
	list_for_each (tmp, dm_table_get_devices(table)) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);

		if (endpos + sizeof(*tdeps->dev) > param->data_end) {
			param->dmi->flags |= DM_BUFFER_FULL_FLAG;
			goto out;
		}
		
		tdeps->dev[tdeps->count++] = dd->bdev->bd_dev;
		endpos += sizeof(*tdeps->dev);
	}

	param->dmi->flags &= ~DM_BUFFER_FULL_FLAG;

      out:
	param->output_size = endpos - (void *) param->dmi;

	dm_table_put(table);
	dm_put(md);

	return 0;
}

static int remove(struct dm_param *param)
{
	struct hash_cell *hc;

	down_write(&_hash_lock);
	hc = __find_device_hash_cell(param->dmi);

	if (!hc) {
		up_write(&_hash_lock);
		return -ENXIO;
	}

	__hash_remove(hc);
	up_write(&_hash_lock);

	return 0;
}

static int remove_all(struct dm_param *param)
{
	dm_hash_remove_all();
	return 0;
}

static int suspend(struct dm_param *param)
{
	int r;
	struct mapped_device *md;

	md = find_device(param->dmi);
	if (!md)
		return -ENXIO;

	if (param->dmi->flags & DM_SUSPEND_FLAG)
		r = dm_suspend(md);
	else
		r = dm_resume(md);

	__info(md, param);

	dm_put(md);

	return r;
}

static int reload(struct dm_param *param)
{
	int r;
	struct mapped_device *md;
	struct dm_table *t;
	struct dm_ioctl *dmi = param->dmi;

	md = find_device(dmi);
	if (!md)
		return -ENXIO;

	r = dm_table_create(&t, get_mode(dmi));
	if (r) {
		dm_put(md);
		return r;
	}

	r = populate_table(t, param);
	if (r) {
		dm_table_put(t);
		dm_put(md);
		return r;
	}

	r = dm_swap_table(md, t);
	dm_table_put(t);	/* md will have taken its own reference */
	if (r) {
		dm_put(md);
		return r;
	}

	set_device_ro(dm_kdev(md), (dmi->flags & DM_READONLY_FLAG) ? 1 : 0);

	__info(md, param);
	dm_put(md);

	return 0;
}

static int rename(struct dm_param *param)
{
	int r;
	struct dm_ioctl *dmi = param->dmi;
	char *new_name = (char *) dmi + dmi->data_offset;

	if (new_name < (char *) (dmi + 1) ||
	    invalid_str(new_name, param->data_end)) {
		DMWARN("Invalid new logical volume name supplied.");
		return -EINVAL;
	}

	r = check_name(new_name);
	if (r)
		return r;

	return dm_hash_rename(dmi->name, new_name);
}

/*-----------------------------------------------------------------
 * Implementation of open/close/ioctl on the special char
 * device.
 *---------------------------------------------------------------*/
static ioctl_fn lookup_ioctl(unsigned int cmd)
{
	static struct {
		int cmd;
		ioctl_fn fn;
	} _ioctls[] = {
		{DM_VERSION_CMD, NULL},	/* version is dealt with elsewhere */
		{DM_REMOVE_ALL_CMD, remove_all},
		{DM_DEV_CREATE_CMD, create},
		{DM_DEV_REMOVE_CMD, remove},
		{DM_DEV_RELOAD_CMD, reload},
		{DM_DEV_RENAME_CMD, rename},
		{DM_DEV_SUSPEND_CMD, suspend},
		{DM_DEV_DEPS_CMD, deps},
		{DM_DEV_STATUS_CMD, info},
		{DM_TARGET_STATUS_CMD, get_status},
		{DM_TARGET_WAIT_CMD, wait_device_event},
	};

	return (cmd >= ARRAY_SIZE(_ioctls)) ? NULL : _ioctls[cmd].fn;
}

/*
 * As well as checking the version compatibility this always
 * copies the kernel interface version out.
 */
static int check_version(unsigned int cmd, struct dm_ioctl *user)
{
	uint32_t version[3];
	int r = 0;

	if (copy_from_user(version, user->version, sizeof(version)))
		return -EFAULT;

	if ((DM_VERSION_MAJOR != version[0]) ||
	    (DM_VERSION_MINOR < version[1])) {
		DMWARN("ioctl interface mismatch: "
		       "kernel(%u.%u.%u), user(%u.%u.%u), cmd(%d)",
		       DM_VERSION_MAJOR, DM_VERSION_MINOR,
		       DM_VERSION_PATCHLEVEL,
		       version[0], version[1], version[2], cmd);
		r = -EINVAL;
	}

	/*
	 * Fill in the kernel version.
	 */
	version[0] = DM_VERSION_MAJOR;
	version[1] = DM_VERSION_MINOR;
	version[2] = DM_VERSION_PATCHLEVEL;
	if (copy_to_user(user->version, version, sizeof(version)))
		return -EFAULT;

	return r;
}

static void free_params(struct dm_param *param)
{
	vfree(param->dmi);
}

static int copy_params(struct dm_ioctl *user, struct dm_param *param)
{
	struct dm_ioctl dmi_tmp, *dmi;

	if (copy_from_user(&dmi_tmp, user, sizeof(dmi_tmp)))
		return -EFAULT;

	if (dmi_tmp.data_size < sizeof(dmi_tmp))
		return -EINVAL;

	dmi = (struct dm_ioctl *) vmalloc(dmi_tmp.data_size);
	if (!dmi)
		return -ENOMEM;

	if (copy_from_user(dmi, user, dmi_tmp.data_size)) {
		vfree(dmi);
		return -EFAULT;
	}

	param->dmi = dmi;
	param->data_end = (void *) dmi + dmi_tmp.data_size - 1;

	return 0;
}

static int validate_params(uint cmd, struct dm_ioctl *dmi)
{
	/* Ignores parameters */
	if (cmd == DM_REMOVE_ALL_CMD)
		return 0;

	/* Unless creating, either name of uuid but not both */
	if (cmd != DM_DEV_CREATE_CMD) {
		if ((!*dmi->uuid && !*dmi->name) ||
		    (*dmi->uuid && *dmi->name)) {
			DMWARN("one of name or uuid must be supplied");
			return -EINVAL;
		}
	}

	/* Ensure strings are terminated */
	dmi->name[DM_NAME_LEN - 1] = '\0';
	dmi->uuid[DM_UUID_LEN - 1] = '\0';

	return 0;
}

static int ctl_ioctl(struct inode *inode, struct file *file,
		     uint command, ulong u)
{
	int r = 0;
	unsigned int cmd;
	struct dm_param param;
	struct dm_ioctl *user = (struct dm_ioctl *) u;
	ioctl_fn fn = NULL;

	/* only root can play with this */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (_IOC_TYPE(command) != DM_IOCTL)
		return -ENOTTY;

	cmd = _IOC_NR(command);

	/*
	 * Check the interface version passed in.  This also
	 * writes out the kernel's interface version.
	 */
	r = check_version(cmd, user);
	if (r)
		return r;

	/*
	 * Nothing more to do for the version command.
	 */
	if (cmd == DM_VERSION_CMD)
		return 0;

	fn = lookup_ioctl(cmd);
	if (!fn) {
		DMWARN("dm_ctl_ioctl: unknown command 0x%x", command);
		return -ENOTTY;
	}

	/*
	 * Copy the parameters into kernel space.
	 */
	r = copy_params(user, &param);
	if (r)
		return r;

	r = validate_params(cmd, param.dmi);
	if (r) {
		free_params(&param);
		return r;
	}

	param.output_size = 0;
	r = fn(&param);
	if (param.output_size)
		results_to_user(user, &param);

	free_params(&param);
	return r;
}

static struct file_operations _ctl_fops = {
	.ioctl	 = ctl_ioctl,
	.owner	 = THIS_MODULE,
};

static devfs_handle_t _ctl_handle;

static struct miscdevice _dm_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = DM_NAME,
	.fops  = &_ctl_fops
};

/*
 * Create misc character device and link to DM_DIR/control.
 */
int __init dm_interface_init(void)
{
	int r;
	char rname[64];

	r = dm_hash_init();
	if (r)
		return r;

	r = misc_register(&_dm_misc);
	if (r) {
		DMERR("misc_register failed for control device");
		dm_hash_exit();
		return r;
	}

	r = devfs_generate_path(_dm_misc.devfs_handle, rname + 3,
				sizeof rname - 3);
	if (r == -ENOSYS)
		goto done;	/* devfs not present */

	if (r < 0) {
		DMERR("devfs_generate_path failed for control device");
		goto failed;
	}

	strncpy(rname + r, "../", 3);
	r = devfs_mk_symlink(NULL, DM_DIR "/control",
			     DEVFS_FL_DEFAULT, rname + r, &_ctl_handle, NULL);
	if (r) {
		DMERR("devfs_mk_symlink failed for control device");
		goto failed;
	}
	devfs_auto_unregister(_dm_misc.devfs_handle, _ctl_handle);

      done:
	DMINFO("%d.%d.%d%s initialised: %s", DM_VERSION_MAJOR,
	       DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL, DM_VERSION_EXTRA,
	       DM_DRIVER_EMAIL);
	return 0;

      failed:
	misc_deregister(&_dm_misc);
	dm_hash_exit();
	return r;
}

void dm_interface_exit(void)
{
	if (misc_deregister(&_dm_misc) < 0)
		DMERR("misc_deregister failed for control device");

	dm_hash_exit();
}
