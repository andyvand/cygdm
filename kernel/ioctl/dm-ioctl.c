/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"

#include <linux/miscdevice.h>
#include <linux/dm-ioctl.h>

static void free_params(struct dm_ioctl *p)
{
	vfree(p);
}

static int version(struct dm_ioctl *user)
{
        return copy_to_user(user, DM_DRIVER_VERSION, sizeof(DM_DRIVER_VERSION));
}

static int copy_params(struct dm_ioctl *user, struct dm_ioctl **result)
{
	struct dm_ioctl tmp, *dmi;

	if (copy_from_user(&tmp, user, sizeof(tmp)))
		return -EFAULT;

	if (strcmp(DM_IOCTL_VERSION, tmp.version)) {
		DMWARN("dm_ctl_ioctl: struct dm_ioctl version incompatible");
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

	*result = dmi;
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

	if (*spec < (last + 1) || ((void *)*spec > end))
		return -EINVAL;

	return valid_str(*params, begin, end);
}

void dm_error(const char *message)
{
	DMWARN("%s", message);
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

#define PARSE_ERROR(msg) {dm_error(msg); return -EINVAL;}

	for (i = 0; i < args->target_count; i++) {

		r = first ? next_target((struct dm_target_spec *)args, 
					args->data_start,
					begin, end, &spec, &params) :
			    next_target(spec, spec->next, 
					begin, end, &spec, &params);

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
			       argc, argv, &context))  {
			dm_error(context);
			PARSE_ERROR("target constructor failed");
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
 * Copies device info back to user space, used by
 * the create and info ioctls.
 */
static int info(const char *name, struct dm_ioctl *user)
{
	struct dm_ioctl param;
	struct mapped_device *md = dm_get(name);

	param.flags = 0;

	strncpy(param.version, DM_IOCTL_VERSION, sizeof(param.version));

	if (!md)
		goto out;

	param.flags |= DM_EXISTS_FLAG;
	if (md->suspended)
		param.flags |= DM_SUSPEND_FLAG;
	if (md->read_only)
		param.flags |= DM_READONLY_FLAG;

	param.data_size = 0;
	strncpy(param.name, md->name, sizeof(param.name));
	param.name[sizeof(param.name) - 1] = '\0';

	param.open_count = md->use_count;
	param.dev = kdev_t_to_nr(md->dev);
	param.target_count = md->map->num_targets;

	dm_put(md);

      out:
	return copy_to_user(user, &param, sizeof(param));
}

static int create(struct dm_ioctl *param, struct dm_ioctl *user)
{
	int r;
	struct mapped_device *md;
	struct dm_table *t;
	int minor;

	r = dm_table_create(&t);
	if (r)
		return r;

	r = populate_table(t, param);
	if (r)
		goto bad;

	minor = (param->flags & DM_PERSISTENT_DEV_FLAG) ?
		minor = MINOR(to_kdev_t(param->dev)) : -1;

	r = dm_create(param->name, minor, t, &md);
	if (r)
		goto bad;

	dm_set_ro(md, (param->flags & DM_READONLY_FLAG) ? 1 : 0);

	r = info(param->name, user);
	if (r) {
		dm_destroy(md);
		goto bad;
	}

	dm_put(md);
	return 0;

      bad:
	dm_table_destroy(t);
	return r;
}

static int remove(struct dm_ioctl *param)
{
	struct mapped_device *md = dm_get(param->name);

	if (!md)
		return -ENXIO;

	return dm_destroy(md);
}

static int suspend(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md = dm_get(param->name);

	if (!md)
		return -ENXIO;

	r = (param->flags & DM_SUSPEND_FLAG) ? 
	     dm_suspend(md) : dm_resume(md);
	dm_put(md);
	return r;
}

static int reload(struct dm_ioctl *param)
{
	int r;
	struct mapped_device *md = dm_get(param->name);
	struct dm_table *t;

	if (!md)
		return -ENXIO;

	r = dm_table_create(&t);
	if (r)
		goto bad_no_table;

	r = populate_table(t, param);
	if (r)
		goto bad;

	r = dm_swap_table(md, t);
	if (r)
		goto bad;

	dm_set_ro(md, (param->flags & DM_READONLY_FLAG) ? 1 : 0);

	dm_put(md);
	return 0;

      bad:
	dm_table_destroy(t);

      bad_no_table:
	dm_put(md);
	return r;
}

static int rename(struct dm_ioctl *param)
{
	char *newname = (char *) param + param->data_start;
	struct mapped_device *md = dm_get(param->name);

	if (!md)
		return -ENXIO;

	if (valid_str(newname, (void *)param, 
		       (void *)param + param->data_size) ||
	    dm_set_name(md, newname)) {
		dm_error("Invalid new logical volume name supplied.");
		return -EINVAL;
	}

	dm_put(md);
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
		     uint command, ulong a)
{
	int r;
	struct dm_ioctl *p;

	if (command == DM_VERSION)
		return version((struct dm_ioctl *) a);

	r = copy_params((struct dm_ioctl *) a, &p);
	if (r)
		return r;

	switch (command) {
	case DM_CREATE:
		r = create(p, (struct dm_ioctl *) a);
		break;

	case DM_REMOVE:
		r = remove(p);
		break;

	case DM_SUSPEND:
		r = suspend(p);
		break;

	case DM_RELOAD:
		r = reload(p);
		break;

	case DM_INFO:
		r = info(p->name, (struct dm_ioctl *) a);
		break;

	case DM_RENAME:
		r = rename(p);
		break;

	default:
		DMWARN("dm_ctl_ioctl: unknown command 0x%x", command);
		r = -EINVAL;
	}

	free_params(p);
	return r;
}

static struct file_operations _ctl_fops = {
	open:		ctl_open,
	release:	ctl_close,
	ioctl:		ctl_ioctl,
	owner:		THIS_MODULE,
};

static devfs_handle_t _ctl_handle;

static struct miscdevice _dm_misc = {
	minor:		MISC_DYNAMIC_MINOR,
	name:		DM_NAME,
	fops:		&_ctl_fops
};

/* Create misc character device and link to DM_DIR/control */
int dm_interface_init(void)
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
		return 0; 	/* devfs not present */

	if (r < 0) {
		DMERR("devfs_generate_path failed for control device");
		goto failed;
	}

	strncpy(rname + r, "../", 3);
	r = devfs_mk_symlink(NULL, DM_DIR "/control", 
			     DEVFS_FL_DEFAULT, rname + r,
			     &_ctl_handle, NULL);
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
