/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/miscdevice.h>
#include <linux/dm-ioctl.h>
#include <linux/init.h>
#include <linux/wait.h>

static void free_params(struct dm_ioctl *param)
{
	vfree(param);
}

static int version(struct dm_ioctl *user)
{
	return copy_to_user(user, DM_DRIVER_VERSION, sizeof(DM_DRIVER_VERSION));
}

static int copy_params(struct dm_ioctl *user, struct dm_ioctl **param)
{
	struct dm_ioctl tmp, *dmi;

	if (copy_from_user(&tmp, user, sizeof(tmp)))
		return -EFAULT;

	if (strcmp(DM_IOCTL_VERSION, tmp.version)) {
		DMWARN("struct dm_ioctl version incompatible");
		return -EINVAL;
	}

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
	/* Unless creating, either name of uuid but not both */
	if (cmd != DM_CREATE_CMD) {
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

/*
 * Check a string doesn't overrun the chunk of
 * memory we copied from userland.
 */
static int valid_str(char *str, void *begin, void *end)
{
	while (((void *) str >= begin) && ((void *) str < end))
		if (!*str++)
			return 0;

	return -EINVAL;
}

static int next_target(struct dm_target_spec *last, unsigned long next,
		       void *begin, void *end,
		       struct dm_target_spec **spec, char **params)
{
	*spec = (struct dm_target_spec *)
	    ((unsigned char *) last + next);
	*params = (char *) (*spec + 1);

	if (*spec < (last + 1) || ((void *) *spec > end))
		return -EINVAL;

	return valid_str(*params, begin, end);
}

/*
 * Checks to see if there's a gap in the table.
 * Returns true iff there is a gap.
 */
static int gap(struct dm_table *table, struct dm_target_spec *spec)
{
	if (!table->num_targets)
		return (spec->sector_start > 0) ? 1 : 0;

	if (spec->sector_start != table->highs[table->num_targets - 1] + 1)
		return 1;

	return 0;
}

static int populate_table(struct dm_table *table, struct dm_ioctl *args)
{
	int i = 0, r, first = 1, argc;
	struct dm_target_spec *spec;
	char *params, *argv[MAX_ARGS];
	struct target_type *ttype;
	void *context, *begin, *end;
	offset_t highs = 0;

	if (!args->target_count) {
		DMWARN("populate_table: no targets specified");
		return -EINVAL;
	}

	begin = (void *) args;
	end = begin + args->data_size;

#define PARSE_ERROR(msg) {DMWARN(msg); return -EINVAL;}

	for (i = 0; i < args->target_count; i++) {

		r = first ? next_target((struct dm_target_spec *) args,
					args->data_start,
					begin, end, &spec, &params) :
		    next_target(spec, spec->next, begin, end, &spec, &params);

		if (r)
			PARSE_ERROR("unable to find target");

		/* Look up the target type */
		ttype = dm_get_target_type(spec->target_type);
		if (!ttype)
			PARSE_ERROR("unable to find target type");

		if (gap(table, spec))
			PARSE_ERROR("gap in target ranges");

		/* Split up the parameter list */
		if (split_args(MAX_ARGS, &argc, argv, params) < 0)
			PARSE_ERROR("Too many arguments");

		/* Build the target */
		if (ttype->ctr(table, spec->sector_start, spec->length,
			       argc, argv, &context)) {
			DMWARN("%s: target constructor failed",
			       (char *) context);
			return -EINVAL;
		}

		/* Add the target to the table */
		highs = spec->sector_start + (spec->length - 1);
		if (dm_table_add_target(table, highs, ttype, context))
			PARSE_ERROR("internal error adding target to table");

		first = 0;
	}

#undef PARSE_ERROR

	r = dm_table_complete(table);
	return r;
}

/*
 * Round up the ptr to the next 'align' boundary.  Obviously
 * 'align' must be a power of 2.
 */
static inline void *align_ptr(void *ptr, unsigned int align)
{
	align--;
	return (void *) (((unsigned long) (ptr + align)) & ~align);
}

/*
 * Copies a dm_ioctl and an optional additional payload to
 * userland.
 */
static int results_to_user(struct dm_ioctl *user, struct dm_ioctl *param,
			   void *data, unsigned long len)
{
	int r;
	void *ptr = NULL;

	strncpy(param->version, DM_IOCTL_VERSION, sizeof(param->version));

	if (data) {
		ptr = align_ptr(user + 1, sizeof(unsigned long));
		param->data_start = ptr - (void *) user;
	}

	r = copy_to_user(user, param, sizeof(*param));
	if (r)
		return r;

	if (data) {
		if (param->data_start + len > param->data_size)
			return -ENOSPC;
		r = copy_to_user(ptr, data, len);
	}

	return r;
}

/*
 * Fills in a dm_ioctl structure, ready for sending back to
 * userland.
 */
static void __info(struct mapped_device *md, struct dm_ioctl *param)
{
	param->flags = DM_EXISTS_FLAG;
	if (md->suspended)
		param->flags |= DM_SUSPEND_FLAG;
	if (md->read_only)
		param->flags |= DM_READONLY_FLAG;

	strncpy(param->name, md->name, sizeof(param->name));

	if (md->uuid)
		strncpy(param->uuid, md->uuid, sizeof(param->uuid) - 1);
	else
		param->uuid[0] = '\0';

	param->open_count = md->use_count;
	param->dev = kdev_t_to_nr(md->dev);
	param->target_count = md->map->num_targets;
}

/*
 * Always use UUID for lookups if it's present, otherwise use name.
 */
static inline char *lookup_name(struct dm_ioctl *param)
{
	return (*param->uuid) ? param->uuid : param->name;
}

static inline int lookup_type(struct dm_ioctl *param)
{
	return (*param->uuid) ? DM_LOOKUP_BY_UUID : DM_LOOKUP_BY_NAME;
}

#define ALIGNMENT sizeof(int)
static void *_align(void *ptr, unsigned int a)
{
	register unsigned long align = --a;

	return (void *) (((unsigned long) ptr + align) & ~align);
}

/*
 * Build up the status struct for each target
 */
static int __status(struct mapped_device *md, struct dm_ioctl *param,
		    char *outbuf, int *len)
{
	int i;
	struct dm_target_spec *spec;
	unsigned long long sector = 0LL;
	char *outptr;
	status_type_t type;

	if (param->flags & DM_STATUS_TABLE_FLAG)
		type = STATUSTYPE_TABLE;
	else
		type = STATUSTYPE_INFO;

	outptr = outbuf;

	/* Get all the target info */
	for (i = 0; i < md->map->num_targets; i++) {
		struct target_type *tt = md->map->targets[i].type;
		offset_t high = md->map->highs[i];

		if (outptr - outbuf +
		    sizeof(struct dm_target_spec) > param->data_size)
			    return -ENOMEM;

		spec = (struct dm_target_spec *) outptr;

		spec->status = 0;
		spec->sector_start = sector;
		spec->length = high - sector + 1;
		strncpy(spec->target_type, tt->name, sizeof(spec->target_type));

		outptr += sizeof(struct dm_target_spec);

		/* Get the status/table string from the target driver */
		if (tt->status)
			tt->status(type, outptr,
				   outbuf + param->data_size - outptr,
				   md->map->targets[i].private);
		else
			outptr[0] = '\0';

		outptr += strlen(outptr) + 1;
		_align(outptr, ALIGNMENT);

		sector = high + 1;

		spec->next = outptr - outbuf;
	}

	param->target_count = md->map->num_targets;
	*len = outptr - outbuf;

	return 0;
}

/*
 * Return the status of a device as a text string for each
 * target.
 */
static int get_status(struct dm_ioctl *param, struct dm_ioctl *user)
{
	struct mapped_device *md;
	int len = 0;
	int ret;
	char *outbuf = NULL;

	md = dm_get_name_r(lookup_name(param), lookup_type(param));
	if (!md)
		/*
		 * Device not found - returns cleared exists flag.
		 */
		goto out;

	/* We haven't a clue how long the resultant data will be so
	   just allocate as much as userland has allowed us and make sure
	   we don't overun it */
	outbuf = kmalloc(param->data_size, GFP_KERNEL);
	if (!outbuf)
		goto out;
	/*
	 * Get the status of all targets
	 */
	__status(md, param, outbuf, &len);

	/*
	 * Setup the basic dm_ioctl structure.
	 */
	__info(md, param);

      out:
	if (md)
		dm_put_r(md);

	ret = results_to_user(user, param, outbuf, len);

	if (outbuf)
		kfree(outbuf);

	return ret;
}

/*
 * Wait for a device to report an event
 */
static int wait_device_event(struct dm_ioctl *param, struct dm_ioctl *user)
{
	struct mapped_device *md;
	DECLARE_WAITQUEUE(wq, current);

	md = dm_get_name_r(lookup_name(param), lookup_type(param));
	if (!md)
		/*
		 * Device not found - returns cleared exists flag.
		 */
		goto out;
	/*
	 * Setup the basic dm_ioctl structure.
	 */
	__info(md, param);

	/*
	 * Wait for a notification event
	 */
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&md->map->eventq, &wq);

	dm_put_r(md);

	schedule();
	set_current_state(TASK_RUNNING);

      out:
	return results_to_user(user, param, NULL, 0);
}

/*
 * Copies device info back to user space, used by
 * the create and info ioctls.
 */
static int info(struct dm_ioctl *param, struct dm_ioctl *user)
{
	struct mapped_device *md;

	param->flags = 0;

	md = dm_get_name_r(lookup_name(param), lookup_type(param));
	if (!md)
		/*
		 * Device not found - returns cleared exists flag.
		 */
		goto out;

	__info(md, param);
	dm_put_r(md);

      out:
	return results_to_user(user, param, NULL, 0);
}

/*
 * Retrieves a list of devices used by a particular dm device.
 */
static int dep(struct dm_ioctl *param, struct dm_ioctl *user)
{
	int count, r;
	struct mapped_device *md;
	struct list_head *tmp;
	size_t len = 0;
	struct dm_target_deps *deps = NULL;

	md = dm_get_name_r(lookup_name(param), lookup_type(param));
	if (!md)
		goto out;

	/*
	 * Setup the basic dm_ioctl structure.
	 */
	__info(md, param);

	/*
	 * Count the devices.
	 */
	count = 0;
	list_for_each(tmp, &md->map->devices)
	    count++;

	/*
	 * Allocate a kernel space version of the dm_target_status
	 * struct.
	 */
	if (array_too_big(sizeof(*deps), sizeof(*deps->dev), count)) {
		dm_put_r(md);
		return -ENOMEM;
	}

	len = sizeof(*deps) + (sizeof(*deps->dev) * count);
	deps = kmalloc(len, GFP_KERNEL);
	if (!deps) {
		dm_put_r(md);
		return -ENOMEM;
	}

	/*
	 * Fill in the devices.
	 */
	deps->count = count;
	count = 0;
	list_for_each(tmp, &md->map->devices) {
		struct dm_dev *dd = list_entry(tmp, struct dm_dev, list);
		deps->dev[count++] = kdev_t_to_nr(dd->dev);
	}
	dm_put_r(md);

      out:
	r = results_to_user(user, param, deps, len);

	kfree(deps);
	return r;
}

static int create(struct dm_ioctl *param, struct dm_ioctl *user)
{
	int r, ro;
	struct dm_table *t;
	int minor;

	r = dm_table_create(&t);
	if (r)
		return r;

	r = populate_table(t, param);
	if (r) {
		dm_table_destroy(t);
		return r;
	}

	minor = (param->flags & DM_PERSISTENT_DEV_FLAG) ?
	    MINOR(to_kdev_t(param->dev)) : -1;

	ro = (param->flags & DM_READONLY_FLAG) ? 1 : 0;

	r = dm_create(param->name, param->uuid, minor, ro, t);
	if (r) {
		dm_table_destroy(t);
		return r;
	}

	r = info(param, user);
	return r;
}

static int remove(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md;

	md = dm_get_name_w(lookup_name(param), lookup_type(param));
	if (!md)
		return -ENXIO;

	r = dm_destroy(md);
	dm_put_w(md);
	if (!r)
		kfree(md);

	return r;
}

static int suspend(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md;

	md = dm_get_name_w(lookup_name(param), lookup_type(param));
	if (!md)
		return -ENXIO;

	r = (param->flags & DM_SUSPEND_FLAG) ? dm_suspend(md) : dm_resume(md);
	dm_put_w(md);

	return r;
}

static int reload(struct dm_ioctl *param, struct dm_ioctl *user)
{
	int r;
	struct mapped_device *md;
	struct dm_table *t;

	r = dm_table_create(&t);
	if (r)
		return r;

	r = populate_table(t, param);
	if (r) {
		dm_table_destroy(t);
		return r;
	}

	md = dm_get_name_w(lookup_name(param), lookup_type(param));
	if (!md) {
		dm_table_destroy(t);
		return -ENXIO;
	}

	r = dm_swap_table(md, t);
	if (r) {
		dm_put_w(md);
		dm_table_destroy(t);
		return r;
	}

	dm_set_ro(md, (param->flags & DM_READONLY_FLAG) ? 1 : 0);
	dm_put_w(md);

	r = info(param, user);
	return r;
}

static int rename(struct dm_ioctl *param)
{
	char *newname = (char *) param + param->data_start;

	if (valid_str(newname, (void *) param,
		      (void *) param + param->data_size) ||
	    dm_set_name(lookup_name(param), lookup_type(param), newname)) {
		DMWARN("Invalid new logical volume name supplied.");
		return -EINVAL;
	}

	return 0;
}

static int ctl_open(struct inode *inode, struct file *file)
{
	/* only root can open this */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	MOD_INC_USE_COUNT;

	return 0;
}

static int ctl_close(struct inode *inode, struct file *file)
{
	MOD_DEC_USE_COUNT;
	return 0;
}

static int ctl_ioctl(struct inode *inode, struct file *file,
		     uint command, ulong u)
{
	int r = 0;
	struct dm_ioctl *param;
	struct dm_ioctl *user = (struct dm_ioctl *) u;
	uint cmd = _IOC_NR(command);

	/* Process commands without params first - always return version */
	switch (cmd) {
	case DM_REMOVE_ALL_CMD:
		dm_destroy_all();
	case DM_VERSION_CMD:
		return version(user);
	default:
		break;
	}

	r = copy_params(user, &param);
	if (r)
		goto err;

	r = validate_params(cmd, param);
	if (r) {
		free_params(param);
		goto err;
	}

	switch (cmd) {
	case DM_INFO_CMD:
		r = info(param, user);
		break;

	case DM_SUSPEND_CMD:
		r = suspend(param);
		break;

	case DM_CREATE_CMD:
		r = create(param, user);
		break;

	case DM_RELOAD_CMD:
		r = reload(param, user);
		break;

	case DM_REMOVE_CMD:
		r = remove(param);
		break;

	case DM_RENAME_CMD:
		r = rename(param);
		break;

	case DM_DEPS_CMD:
		r = dep(param, user);
		break;

	case DM_GET_STATUS_CMD:
		r = get_status(param, user);
		break;

	case DM_WAIT_EVENT_CMD:
		r = wait_device_event(param, user);
		break;

	default:
		DMWARN("dm_ctl_ioctl: unknown command 0x%x", command);
		r = -ENOTTY;
	}

	free_params(param);
	return r;

      err:
	version(user);
	return r;
}

static struct file_operations _ctl_fops = {
	open:	ctl_open,
	release:ctl_close,
	ioctl:	ctl_ioctl,
	owner:	THIS_MODULE,
};

static devfs_handle_t _ctl_handle;

static struct miscdevice _dm_misc = {
	minor:	MISC_DYNAMIC_MINOR,
	name:	DM_NAME,
	fops:	&_ctl_fops
};

/* Create misc character device and link to DM_DIR/control */
int __init dm_interface_init(void)
{
	int r;
	char rname[64];

	r = misc_register(&_dm_misc);
	if (r) {
		DMERR("misc_register failed for control device");
		return r;
	}

	r = devfs_generate_path(_dm_misc.devfs_handle, rname + 3,
				sizeof rname - 3);
	if (r == -ENOSYS)
		return 0;	/* devfs not present */

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

	return 0;

      failed:
	misc_deregister(&_dm_misc);
	return r;
}

void dm_interface_exit(void)
{
	if (misc_deregister(&_dm_misc) < 0)
		DMERR("misc_deregister failed for control device");
}
