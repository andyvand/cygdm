/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

#include "libdevmapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <errno.h>
#include <linux/kdev_t.h>

#define DEV_DIR "/dev/"

/* FIXME Obtain from kernel header */
#define DM_DIR "device-mapper"

static char _dm_dir[PATH_MAX] = DEV_DIR DM_DIR;

typedef enum {
	DIR_CREATE,
	DIR_REMOVE
} do_newold_t;

/*
 * Library users can provide their own logging
 * function.
 */
static void _default_log(int level, const char *file, int line,
			 const char *f, ...)
{
	va_list ap;

	va_start(ap, f);
	vfprintf(stderr, f, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

static dm_log_fn _log = _default_log;

void dm_log_init(dm_log_fn fn)
{
	_log = fn;
}

#define log(msg, x...) _log(1, __FILE__, __LINE__, msg, ## x)

struct target {
	struct target *next;
	char *str;
};

struct dm_task {
	int type;
	char *dev_name;

	struct target *head, *tail;

	struct dm_info info;
};

#define NR_ARGS 16

/*
 * Join n path components together with /'s.
 */
static char *mkpath(int n, ...)
{
	va_list va;
	int len = 0, i;
	char *str, *r;

	va_start(va, n);
	for (i = 0; i < n; i++)
		len += strlen(va_arg(va, char *)) + 1;

	va_end(va);

	if (!(r = str = malloc(len))) {
		log("mkpath: malloc(%d) failed", len);
		return NULL;
	}

	va_start(va, n);
	for (i = 0; i < n; i++)
		str += sprintf(str, "%s%s", i ? "/" : "", va_arg(va, char *));
	va_end(va);

	return r;
}

struct dm_task *dm_task_create(int type)
{
	struct dm_task *dmt = malloc(sizeof(*dmt));

	if (!dmt) {
		log("dm_task_create: malloc(%d) failed", sizeof(*dmt));
		return NULL;
	}

	memset(dmt, 0, sizeof(*dmt));

	dmt->type = type;
	return dmt;
}

void dm_task_destroy(struct dm_task *dmt)
{
	struct target *t, *n;

	for (t = dmt->head; t; t = n) {
		n = t->next;
		free(t);
	}
	if (dmt->dev_name)
		free(dmt->dev_name);
	free(dmt);
}

int dm_task_set_name(struct dm_task *dmt, const char *name)
{
	if (dmt->dev_name)
		free(dmt->dev_name);

	return (dmt->dev_name = strdup(name)) ? 1 : 0;
}

int dm_task_get_info(struct dm_task *dmt, struct dm_info *info)
{
	memcpy(info, &dmt->info, sizeof(struct dm_info));
	return 1;
}

static struct target *_create_target(unsigned long long start,
				     unsigned long long len,
				     const char *type, const char *params)
{
	struct target *t;
	int size = strlen(params) + strlen(type);
	int ret;

	size += 64;		/* Guess at max size of start and len */

	t = malloc(size + sizeof(struct target));
	if (!t) {
		log("_create_target: malloc(%d) failed",
		    size + sizeof(struct target));
		return NULL;
	}

	memset(t, 0, size + sizeof(struct target));
	t->str = (char *) (t + 1);

	ret = sprintf(t->str, "%Lu %Lu %s %s\n", start, len, type, params);
	if (ret > size) {
		/* This should be impossible, but check anyway */
		log("_create_target internal error: Ran out of buffer space");
		free(t);
		return NULL;
	}

	return t;
}

int dm_task_add_target(struct dm_task *dmt,
		       unsigned long long start,
		       unsigned long long size,
		       const char *ttype, const char *params)
{
	struct target *t = _create_target(start, size, ttype, params);

	if (!t)
		return 0;

	if (!dmt->head)
		dmt->head = dmt->tail = t;
	else {
		dmt->tail->next = t;
		dmt->tail = t;
	}

	return 1;
}

static void _build_dev_path(char *buffer, size_t len, const char *dev_name)
{
	snprintf(buffer, len, "/dev/%s/%s", DM_DIR, dev_name);
}

static int _add_dev_node(const char *dev_name, dev_t dev)
{
	char path[PATH_MAX];
	struct stat info;

	_build_dev_path(path, sizeof(path), dev_name);

	if (stat(path, &info) >= 0) {
		if (!S_ISBLK(info.st_mode)) {
			log("A non-block device file at '%s' "
			    "is already present", path);
			return 0;
		}

		if (info.st_rdev == dev)
			return 1;

		if (unlink(path) < 0) {
			log("Unable to unlink device node for '%s'", dev_name);
			return 0;
		}
	}

	if (mknod(path, S_IFBLK | S_IRUSR | S_IWUSR | S_IRGRP, dev) < 0) {
		log("Unable to make device node for '%s'", dev_name);
		return 0;
	}

	return 1;
}

static int _rm_dev_node(const char *dev_name)
{
	char path[PATH_MAX];
	struct stat info;

	_build_dev_path(path, sizeof(path), dev_name);

	if (stat(path, &info) < 0)
		return 1;

	if (unlink(path) < 0) {
		log("Unable to unlink device node for '%s'", dev_name);
		return 0;
	}

	return 1;
}

static int do_suspend(char *mnt, char *name, int on)
{
	char *path;
	FILE *fp;
	int ret = 0;

	if (!(path = mkpath(3, mnt, name, "suspend")))
		return 0;

	if ((fp = fopen(path, "rw"))) {
		if (fprintf(fp, "%d\n", on) > 0)
			ret = 1;
		else
			log("%s: fprintf failed: %s", path, strerror(errno));
		fclose(fp);
	} else
		log("%s: fopen failed: %s", path, strerror(errno));

	free(path);

	return ret;
}

static int do_newold(char *mnt, char *name, do_newold_t create)
{
	char *path = mkpath(2, mnt, name);
	int ret;

	if (!path)
		return 0;

	if (create == DIR_CREATE) {
		if ((ret = mkdir(path, 0750)) < 0)
			log("%s: mkdir failed: %s", path, strerror(errno));
	} else if ((ret = rmdir(path)) < 0)
		log("%s: rmdir failed: %s", path, strerror(errno));

	free(path);

	return (ret < 0) ? 0 : 1;
}

static int do_device(char *mnt, char *name, struct dm_info *info)
{
	char *path;
	struct stat st;

	if (!(path = mkpath(3, mnt, name, "device")))
		return 0;

	if (!stat(path, &st)) {
		info->major = MAJOR(st.st_rdev);
		info->minor = MINOR(st.st_rdev);
		info->exists = 1;
	} else
		info->exists = 0;

	free(path);
	return 1;
}

static int do_suspend_state(char *mnt, char *name, struct dm_info *info)
{
	char *path;
	FILE *fp;
	int ret = 0;

	if (!(path = mkpath(3, mnt, name, "suspend")))
		return 0;

	if ((fp = fopen(path, "r"))) {
		if (fscanf(fp, "%d", &info->suspended) == 1)
			ret = 1;
		else
			log("%s fscanf failed: %s", path, strerror(errno));
		fclose(fp);
	} else
		log("%s: fopen failed: %s", path, strerror(errno));

	free(path);

	return ret;
}

static int do_info(char *mnt, char *name, struct dm_info *info)
{
	memset(info, 0, sizeof(struct dm_info));

	if (!do_device(mnt, name, info))
		return 0;

	if (info->exists && !do_suspend_state(mnt, name, info))
		return 0;

	return 1;
}

/*
 * Writes a buffer out to a file, returns 0 on failure.
 */
static int write_buffer(int fd, const void *buf, size_t count)
{
	size_t n = 0;
	int tot = 0;

	while (tot < count) {
		do
			n = write(fd, buf, count - tot);
		while ((n < 0) && ((errno == EINTR) || (errno == EAGAIN)));

		if (n <= 0)
			return 0;

		tot += n;
		buf += n;
	}

	return 1;
}

static int write_data(int fd, struct dm_task *dmt)
{
	struct target *t;

	for (t = dmt->head; t; t = t->next)
		if (!write_buffer(fd, t->str, strlen(t->str)))
			return 0;

	return 1;
}

static int do_load(char *mnt, char *name, struct dm_task *dmt)
{
	char *path;
	int fd, ret = 0;

	if (!(path = mkpath(3, mnt, name, "table")))
		return 0;

	if ((fd = open(path, O_RDWR)) != -1) {
		if (!(ret = write_data(fd, dmt)))
			log("%s: write failed: %s", path, strerror(errno));
		close(fd);
	}

	free(path);

	return ret;
}

static void strip_nl(char *str)
{
	while (*str && *str != '\n' && *str != '\r')
		str++;
	*str = 0;
}

static int do_error_check(char *mnt, char *name)
{
	char *path;
	FILE *fp;
	int ret = 1;
	char buf[1024];

	if (!(path = mkpath(3, mnt, name, "error")))
		return 0;

	if (!(fp = fopen(path, "r"))) {
		log("%s: fopen failed: %s", path, strerror(errno));
		free(path);
		return 0;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		strip_nl(buf);
		log(buf);
		ret = 0;
	}

	fclose(fp);
	free(path);
	return ret;
}

static char *find_mount_point(void)
{
	FILE *fp;
	static char mpoint[4096];
	char fstype[30];

	if ((fp = fopen("/proc/mounts", "r")) < 0) {
		log("/proc/mounts: fopen failed: %s", strerror(errno));
		return NULL;
	}

	while (fscanf(fp, "%*s%4096s%30s%*s%*d%*d", mpoint, fstype) == 2) {
		if (!strcmp(fstype, "dmfs")) {
			fclose(fp);
			return mpoint;
		}
	}
	fclose(fp);
	return NULL;
}

int dm_task_run(struct dm_task *dmt)
{
	char *mnt = find_mount_point();

	if (mnt == NULL) {
		/* FIXME Mount it temporarily if not mounted */
		log("Cannot find mount point for dmfs or dmfs not mounted");
		return 0;
	}

	if (!dmt->dev_name || !*dmt->dev_name) {
		log("dm_task_run: Device name not supplied");
		return 0;
	}

	switch (dmt->type) {
	case DM_DEVICE_CREATE:
		if (!do_newold(mnt, dmt->dev_name, DIR_CREATE) ||
		    !do_load(mnt, dmt->dev_name, dmt) ||
		    !do_error_check(mnt, dmt->dev_name) ||
		    !do_info(mnt, dmt->dev_name, &dmt->info))
			return 0;
		_add_dev_node(dmt->dev_name,
			      MKDEV(dmt->info.major, dmt->info.minor));
		break;

	case DM_DEVICE_RELOAD:
		if (!do_load(mnt, dmt->dev_name, dmt) ||
		    !do_error_check(mnt, dmt->dev_name)) return 0;
		break;

	case DM_DEVICE_REMOVE:
		if (!do_newold(mnt, dmt->dev_name, DIR_REMOVE) ||
		    !do_info(mnt, dmt->dev_name, &dmt->info))
			return 0;
		_rm_dev_node(dmt->dev_name);
		break;

	case DM_DEVICE_SUSPEND:
		if (!do_suspend(mnt, dmt->dev_name, 1))
			return 0;
		break;

	case DM_DEVICE_RESUME:
		if (!do_suspend(mnt, dmt->dev_name, 0))
			return 0;
		break;

	case DM_DEVICE_INFO:
		if (!do_info(mnt, dmt->dev_name, &dmt->info))
			return 0;
		break;

	default:
		log("Internal error: unknown device-mapper task %d", dmt->type);
		return 0;
	}

	return 1;
}

int dm_set_dev_dir(const char *dir)
{
	snprintf(_dm_dir, sizeof(_dm_dir), "%s%s", dir, DM_DIR);
	return 1;
}

const char *dm_dir(void)
{
	return _dm_dir;
}