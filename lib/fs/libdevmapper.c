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
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <linux/kdev_t.h>
#include <linux/device-mapper.h>

#include "libdm-targets.h"
#include "libdm-common.h"

typedef enum {
	DIR_CREATE,
	DIR_REMOVE
} do_newold_t;

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

int dm_task_get_info(struct dm_task *dmt, struct dm_info *info)
{
	memcpy(info, &dmt->info, sizeof(struct dm_info));
	return 1;
}

struct target *create_target(uint64_t start,
				     uint64_t len,
				     const char *type, const char *params)
{
	struct target *t;
	int size = strlen(params) + strlen(type);
	int ret;

	size += 64;		/* Guess at max size of start and len */

	t = malloc(size + sizeof(struct target));
	if (!t) {
		log("create_target: malloc(%d) failed",
		    size + sizeof(struct target));
		return NULL;
	}

	memset(t, 0, size + sizeof(struct target));
	t->str = (char *) (t + 1);

	ret = sprintf(t->str, "%"PRIu64" %"PRIu64" %s %s\n", start, len, 
		      type, params);
	if (ret > size) {
		/* This should be impossible, but check anyway */
		log("create_target internal error: Ran out of buffer space");
		free(t);
		return NULL;
	}

	return t;
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
		add_dev_node(dmt->dev_name,
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
		rm_dev_node(dmt->dev_name);
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

