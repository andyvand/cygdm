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

/*
 * All the ioctl commands get dispatched to functions with this
 * prototype.
 */
typedef int (*ioctl_fn)(struct dm_ioctl *param);

/*
 * Check a string doesn't overrun the chunk of
 * memory we copied from userland.
 */
static int invalid_str(char *str, void *end)
{
	while ((void *) str < end)
		if (!*str++)
			return 0;

	return -EINVAL;
}

static int next_target(struct dm_target_spec *last, uint32_t next, void *end,
		       struct dm_target_spec **spec, char **target_params)
{
	*spec = (struct dm_target_spec *) ((unsigned char *) last + next);
	*target_params = (char *) (*spec + 1);

	if (*spec < (last + 1))
		return -EINVAL;

	return invalid_str(*target_params, end);
}

static int populate_table(struct dm_table *table, struct dm_ioctl *param)
{
	int r;
	unsigned int i = 0;
	struct dm_target_spec *spec = (struct dm_target_spec *) param;
	uint32_t next = param->data_start;
	void *end = (void *) param + param->data_size;
	char *target_params;

	if (!param->target_count) {
		DMWARN("populate_table: no targets specified");
		return -EINVAL;
	}

	for (i = 0; i < param->target_count; i++) {

		r = next_target(spec, next, end, &spec, &target_params);
		if (r) {
			DMWARN("unable to find target");
			return r;
		}

		r = dm_table_add_target(table, spec->target_type,
					(sector_t) spec->sector_start,
					(sector_t) spec->length,
					target_params);
		if (r) {
			DMWARN("error adding target to table");
			return r;
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

/*
 * Fills in a dm_ioctl structure, ready for sending back to
 * userland.
 */
static int __info(struct mapped_device *md, struct dm_ioctl *param)
{
	kdev_t dev = dm_kdev(md);
	struct dm_table *table;
	struct block_device *bdev;

	param->data_size = sizeof(*param);
	param->flags &= ~(DM_SUSPEND_FLAG | DM_READONLY_FLAG);

	if (dm_suspended(md))
		param->flags |= DM_SUSPEND_FLAG;

	param->dev = kdev_t_to_nr(dev);

	if (is_read_only(dev))
		param->flags |= DM_READONLY_FLAG;

	param->event_nr = dm_get_event_nr(md);

	table = dm_get_table(md);
	param->target_count = dm_table_get_num_targets(table);
	dm_table_put(table);

	bdev = bdget(param->dev);
	if (!bdev)
		return -ENXIO;
	param->open_count = bdev->bd_openers;
	bdput(bdev);

	return 0;
}

/*
 * Always use UUID for lookups if it's present, otherwise use name.
 */

static inline struct hash_cell *__find_device_hash_cell(struct dm_ioctl *param)
{
	return *param->uuid ?
	    __get_uuid_cell(param->uuid) : __get_name_cell(param->name);
}

static inline struct mapped_device *find_device(struct dm_ioctl *param)
{
	struct hash_cell *hc;
	struct mapped_device *md = NULL;

	down_read(&_hash_lock);
	hc = __find_device_hash_cell(param);
	if (hc) {
		md = hc->md;

		/*
		 * Sneakily write in both the name and the uuid
		 * while we have the cell.
		 */
		strncpy(param->name, hc->name, sizeof(param->name));
		if (hc->uuid)
			strncpy(param->uuid, hc->uuid, sizeof(param->uuid) - 1);
		else
			param->uuid[0] = '\0';

		dm_get(md);
	}
	up_read(&_hash_lock);

	return md;
}

/*
 * Copies device info back to user space, used by
 * the create and info ioctls.
 */
static int info(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md;

	md = find_device(param);
	if (!md)
		return -ENXIO;

	r = __info(md, param);
	dm_put(md);
	return r;
}

static inline int get_mode(struct dm_ioctl *param)
{
	int mode = FMODE_READ | FMODE_WRITE;

	if (param->flags & DM_READONLY_FLAG)
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

static int create(struct dm_ioctl *param)
{
	int r;
	kdev_t dev = 0;
	struct dm_table *t;
	struct mapped_device *md;

	r = check_name(param->name);
	if (r)
		return r;

	r = dm_table_create(&t, get_mode(param));
	if (r)
		return r;

	r = populate_table(t, param);
	if (r) {
		dm_table_put(t);
		return r;
	}

	if (param->flags & DM_PERSISTENT_DEV_FLAG)
		dev = to_kdev_t(param->dev);

	r = dm_create(dev, t, &md);
	dm_table_put(t);	/* md will have grabbed its own reference */
	if (r)
		return r;

	dev = dm_kdev(md);
	set_device_ro(dev, (param->flags & DM_READONLY_FLAG) ? 1 : 0);
	r = dm_hash_insert(param->name, *param->uuid ? param->uuid : NULL, md);
	if (r) {
		dm_put(md);
		return r;
	}

	r = __info(md, param);
	dm_put(md);

	return r;
}

/*
 * Retrieves the data payload buffer from an already allocated
 * struct dm_ioctl.
 */
static void *get_result_buffer(struct dm_ioctl *param, size_t *len)
{
	param->data_start = align_ptr(param + 1) - (void *) param;

	if (param->data_start < param->data_size)
		*len = param->data_size - param->data_start;
	else
		*len = 0;

	return ((void *) param) + param->data_start;
}

/*
 * Build up the status struct for each target
 */
static int __status(struct mapped_device *md, struct dm_ioctl *param)
{
	int r;
	unsigned int i, num_targets;
	struct dm_target_spec *spec;
	char *outbuf, *outptr;
	status_type_t type;
	struct dm_table *table = dm_get_table(md);
	size_t remaining, len, used = 0;

	outptr = outbuf = get_result_buffer(param, &len);

	r = __info(md, param);
	if (r)
		return r;

	if (param->flags & DM_STATUS_TABLE_FLAG)
		type = STATUSTYPE_TABLE;
	else
		type = STATUSTYPE_INFO;

	/* Get all the target info */
	num_targets = dm_table_get_num_targets(table);
	for (i = 0; i < num_targets; i++) {
		struct dm_target *ti = dm_table_get_target(table, i);

		remaining = len - (outptr - outbuf);
		if (remaining < sizeof(struct dm_target_spec)) {
			param->flags |= DM_BUFFER_FULL_FLAG;
			break;
		}

		spec = (struct dm_target_spec *) outptr;

		spec->status = 0;
		spec->sector_start = ti->begin;
		spec->length = ti->len;
		strncpy(spec->target_type, ti->type->name,
			sizeof(spec->target_type));

		outptr += sizeof(struct dm_target_spec);
		remaining = len - (outptr - outbuf);

		/* Get the status/table string from the target driver */
		if (ti->type->status) {
			if (ti->type->status(ti, type, outptr, remaining)) {
				param->flags |= DM_BUFFER_FULL_FLAG;
				break;
			}
		} else
			outptr[0] = '\0';

		outptr += strlen(outptr) + 1;
		used = param->data_start + (outptr - outbuf);

		align_ptr(outptr);
		spec->next = outptr - outbuf;
	}

	if (used)
		param->data_size = used;

	param->target_count = num_targets;
	dm_table_put(table);

	return 0;
}

/*
 * Return the status of a device as a text string for each
 * target.
 */
static int get_status(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md;

	md = find_device(param);
	if (!md)
		return -ENXIO;

	/*
	 * Get the status of all targets
	 */
	r = __status(md, param);

	dm_put(md);
	return r;
}

/*
 * Wait for a device to report an event
 */
static int wait_device_event(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md;
	DECLARE_WAITQUEUE(wq, current);

	md = find_device(param);
	if (!md)
		return -ENXIO;

	/*
	 * Wait for a notification event
	 */
	set_current_state(TASK_INTERRUPTIBLE);
	if (!dm_add_wait_queue(md, &wq, param->event_nr)) {
		schedule();
		dm_remove_wait_queue(md, &wq);
	}
	set_current_state(TASK_RUNNING);

	/*
	 * The userland program is going to want to know what
	 * changed to trigger the event, so we may as well tell
	 * him and save an ioctl.
	 */
	r = __status(md, param);

	dm_put(md);
	return r;
}

/*
 * Retrieves a list of devices used by a particular dm device.
 */
static int deps(struct dm_ioctl *param)
{
	int r = 0;
	unsigned int count;
	struct mapped_device *md;
	struct list_head *tmp;
	size_t len, needed, used = 0;
	struct dm_target_deps *tdeps = NULL;
	struct dm_table *table;

	md = find_device(param);
	if (!md)
		return -ENXIO;

	table = dm_get_table(md);

	/*
	 * Count the devices.
	 */
	count = 0;
	list_for_each(tmp, dm_table_get_devices(table))
	    count++;

	tdeps = get_result_buffer(param, &len);

	/*
	 * Check we have enough space.
	 */
	needed = sizeof(*tdeps) + (sizeof(*tdeps->dev) * count);
	if (len < needed) {
		param->flags |= DM_BUFFER_FULL_FLAG;
		goto out;
	}
	used = param->data_start + needed;

	/*
	 * Fill in the devices.
	 */
	tdeps->count = count;
	count = 0;
	list_for_each(tmp, dm_table_get_devices(table)) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);
		tdeps->dev[count++] = dd->bdev->bd_dev;
	}

      out:
	r = __info(md, param);

	if (used)
		param->data_size = used;

	dm_table_put(table);
	dm_put(md);
	return r;
}

static int remove(struct dm_ioctl *param)
{
	struct hash_cell *hc;

	down_write(&_hash_lock);
	hc = __find_device_hash_cell(param);

	if (!hc) {
		DMWARN("device doesn't appear to be in the dev hash table.");
		up_write(&_hash_lock);
		return -ENXIO;
	}

	__hash_remove(hc);
	up_write(&_hash_lock);
	param->data_size = 0;
	return 0;
}

static int remove_all(struct dm_ioctl *param)
{
	dm_hash_remove_all();
	param->data_size = 0;
	return 0;
}

/*
 * Set or unset the suspension state of a device.
 * If the device already is in the requested state we just return its info.
 */
static int suspend(struct dm_ioctl *param)
{
	int r = 0;
	struct mapped_device *md;

	md = find_device(param);
	if (!md)
		return -ENXIO;

	if (param->flags & DM_SUSPEND_FLAG) {
		if (!dm_suspended(md))
			r = dm_suspend(md);
	} else if (dm_suspended(md))
		r = dm_resume(md);

	if (!r)
		r = __info(md, param);

	dm_put(md);
	return r;
}

static int reload(struct dm_ioctl *param)
{
	int r;
	kdev_t dev;
	struct mapped_device *md;
	struct dm_table *t;

	r = dm_table_create(&t, get_mode(param));
	if (r)
		return r;

	r = populate_table(t, param);
	if (r) {
		dm_table_put(t);
		return r;
	}

	md = find_device(param);
	if (!md) {
		dm_table_put(t);
		return -ENXIO;
	}

	r = dm_swap_table(md, t);
	if (r) {
		dm_put(md);
		dm_table_put(t);
		return r;
	}
	dm_table_put(t);	/* md will have taken its own reference */

	dev = dm_kdev(md);
	set_device_ro(dev, (param->flags & DM_READONLY_FLAG) ? 1 : 0);
	r = __info(md, param);
	dm_put(md);

	return r;
}

static int rename(struct dm_ioctl *param)
{
	int r;
	char *new_name = (char *) param + param->data_start;

	if (new_name < (char *) (param + 1) ||
	    invalid_str(new_name, (void *) param + param->data_size)) {
		DMWARN("Invalid new logical volume name supplied.");
		return -EINVAL;
	}

	r = check_name(new_name);
	if (r)
		return r;

	param->data_size = 0;
	return dm_hash_rename(param->name, new_name);
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

static void free_params(struct dm_ioctl *param)
{
	vfree(param);
}

static int copy_params(struct dm_ioctl *user, struct dm_ioctl **param)
{
	struct dm_ioctl tmp, *dmi;

	if (copy_from_user(&tmp, user, sizeof(tmp)))
		return -EFAULT;

	if (tmp.data_size < sizeof(tmp))
		return -EINVAL;

	dmi = (struct dm_ioctl *) vmalloc(tmp.data_size);
	if (!dmi)
		return -ENOMEM;

	if (copy_from_user(dmi, user, tmp.data_size)) {
		vfree(dmi);
		return -EFAULT;
	}

	*param = dmi;
	return 0;
}

static int validate_params(uint cmd, struct dm_ioctl *param)
{
	/* Always clear this flag */
	param->flags &= ~DM_BUFFER_FULL_FLAG;

	/* Ignores parameters */
	if (cmd == DM_REMOVE_ALL_CMD)
		return 0;

	/* Unless creating, either name of uuid but not both */
	if (cmd != DM_DEV_CREATE_CMD) {
		if ((!*param->uuid && !*param->name) ||
		    (*param->uuid && *param->name)) {
			DMWARN("one of name or uuid must be supplied");
			return -EINVAL;
		}
	}

	/* Ensure strings are terminated */
	param->name[DM_NAME_LEN - 1] = '\0';
	param->uuid[DM_UUID_LEN - 1] = '\0';

	return 0;
}

static int ctl_ioctl(struct inode *inode, struct file *file,
		     uint command, ulong u)
{
	int r = 0;
	unsigned int cmd;
	struct dm_ioctl *param;
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

	r = validate_params(cmd, param);
	if (r) {
		free_params(param);
		return r;
	}

	r = fn(param);

	/*
	 * Copy the results back to userland.
	 */
	if (!r && copy_to_user(user, param, param->data_size))
		r = -EFAULT;

	free_params(param);
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
