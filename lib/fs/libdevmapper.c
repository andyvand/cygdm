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
#include <errno.h>

#define DEV_DIR "/dev/"
#define DM_DIR "device-mapper"
#define ALIGNMENT sizeof(int)
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MKDEV(x,y) ((x) << 8 | (y))

static char _dm_dir[PATH_MAX] = DEV_DIR DM_DIR;

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

static char *mkpath(int n, char *base, ...)
{
	va_list va;
	char *args[NR_ARGS];
	int len = strlen(base) + 1;
	int i = 0;
	char *str;

	if (n > NR_ARGS)
		return NULL;

	va_start(va, base);
	for(i = 0; i < n; i++) {
		args[i] = (char *)va_arg(va, char *);
		len += strlen(args[i]);
		len++;
	}
	va_end(va);

	str = malloc(len);
	if (str) {
		strcpy(str, base);
		for(i = 0; i < n; i++) {
			strcat(str, "/");
			strcat(str, args[i]);
		}
	}
	return str;
}

struct dm_task *dm_task_create(int type)
{
	struct dm_task *dmt = malloc(sizeof(*dmt));

	if (!dmt)
		return NULL;

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

	size += 64; /* Guess at max size of start and len */

	t = malloc(size + sizeof(struct target));
	if (!t)
		return NULL;
	memset(t, 0, size + sizeof(struct target));
	t->str = (char *)(t + 1);

	ret = sprintf(t->str, "%Lu %Lu %s %s\n", start, len, type, params);
	if (ret > size) {
		/* This should be impossible, but check anyway */
		log("Internal error - ran out of buffer space");
		exit(-1);
	}

	return t;
}

int dm_task_add_target(struct dm_task *dmt,
		       unsigned long long start,
		       unsigned long long size,
		       const char *ttype,
		       const char *params)
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
	char *path = mkpath(2, mnt, name, "suspend");
	int ret = -1;

	if (path) {
		FILE *fp = fopen(path, "rw");
		if (fp) {
			if (fprintf(fp, "%d\n", on) > 0)
				ret = 0;
			fclose(fp);
		}
		free(path);
	}

	return ret;
}

static int do_newold(char *mnt, char *name, int create)
{
	char *path = mkpath(1, mnt, name);
	int ret = -1;

	if (path) {
		if (create)
			ret = mkdir(path, 0750);
		else
			ret = rmdir(path);
		free(path);
	}

	return ret;
}

static int do_device(char *mnt, char *name, struct dm_info *info)
{
	char *path = mkpath(2, mnt, name, "device");
	int ret = -1;
	if (path) {
		struct stat st;
		if (stat(path, &st) == 0) {
			info->major = st.st_rdev >> 8;
			info->minor = st.st_rdev & 0xff;
		}
		free(path);
	}
	return ret;
}

static int do_suspend_state(char *mnt, char *name, struct dm_info *info)
{
	char *path = mkpath(2, mnt, name, "suspend");
	int ret = -1;
	if (path) {
		FILE *fp = fopen(path, "r");
		if (fp) {
			int state;
			if (fscanf(fp, "%d", &state) == 1) {
				info->suspended = state;
				ret = 0;
			}
			fclose(fp);
		}
		free(path);
	}
	return ret;
}

static int do_info(char *mnt, char *name, struct dm_info *info)
{
	int ret;

	memset(info, 0, sizeof(struct dm_info));

	ret = do_device(mnt, name, info);
	if (ret < 0)
		goto out;
	ret = do_suspend_state(mnt, name, info);
	if (ret < 0)
		goto out;
	info->exists = 1;
out:
	return ret;
}

static int write_data(int fd, struct dm_task *dmt)
{
	struct target *tmp = dmt->head;
	int n = 0;
	struct iovec *iov;
	int ret = -1;

	while(tmp) {
		n++;
		tmp = tmp->next;
	}

	iov = malloc(n * sizeof(struct iovec));
	if (iov) {
		tmp = dmt->head;
		n = 0;
		while(tmp) {
			iov[n].iov_base = tmp->str;
			iov[n].iov_len = strlen(tmp->str);
			n++;
			tmp = tmp->next;
		}

		ret = writev(fd, iov, n);
		free(iov);
	}

	return ret;
}

static int do_load(char *mnt, char *name, struct dm_task *dmt)
{
	char *path = mkpath(2, mnt, name, "table");
	int ret = -1;
	if (path) {
		int fd = open(path, O_RDWR);
		if (fd >= 0) {
			ret = write_data(fd, dmt);
			close(fd);
		}
	}
	return ret;
}

static void strip_nl(char *str)
{
	while(*str && *str != '\n' && *str != '\r')
		str++;
	*str = 0;
}

static int do_error_check(char *mnt, char *name)
{
	char *path = mkpath(2, mnt, name, "error");
	int ret = -1;
	if (path) {
		FILE *fp = fopen(path, "r");
		if (fp) {
			char buf[1024];
			ret = 0;
			while(fgets(buf, 1023, fp)) {
				buf[1023] = 0;
				strip_nl(buf);
				log(buf);
				ret = -1;
			}
			fclose(fp);
		}
		free(path);
	}
	return ret;
}

static char *find_mount_point(void)
{
	FILE *fp = fopen("/proc/mounts", "r");
static char mpoint[4096];
	if (fp) {
		int fsdump, fspass;
		char device[1024];
		char fstype[30];
		char fsoptions[4096];
		while(fscanf(fp, "%1024s %4096s %30s %4096s %d %d", device, mpoint, fstype, fsoptions, &fsdump, &fspass) == 6) {
			if (strlen(fstype) != 4)
				continue;
			if (strcmp(fstype, "dmfs"))
				continue;
			fclose(fp);
			return mpoint;
		}
		fclose(fp);
	}
	return NULL;
}

int dm_task_run(struct dm_task *dmt)
{
	char *mnt = find_mount_point();

	if (mnt == NULL) {
		log("Cannot find mount point for dmfs or dmfs not mounted");
		goto bad;
	}

	switch (dmt->type) {
	case DM_DEVICE_CREATE:
		do_newold(mnt, dmt->dev_name, 1);
		do_info(mnt, dmt->dev_name, &dmt->info);
		break;

	case DM_DEVICE_RELOAD:
		do_load(mnt, dmt->dev_name, dmt);
		do_error_check(mnt, dmt->dev_name);
		break;

	case DM_DEVICE_REMOVE:
		do_newold(mnt, dmt->dev_name, 1);
		dmt->info.exists = 0;
		break;

	case DM_DEVICE_SUSPEND:
		do_suspend(mnt, dmt->dev_name, 1);
		break;

	case DM_DEVICE_RESUME:
		do_suspend(mnt, dmt->dev_name, 0);
		break;

	case DM_DEVICE_INFO:
		do_info(mnt, dmt->dev_name, &dmt->info);
		break;

	default:
		log("Internal error: unknown device-mapper task %d",
		    dmt->type);
		goto bad;
	}

	switch (dmt->type) {
	case DM_DEVICE_CREATE:
		_add_dev_node(dmt->dev_name,
			      MKDEV(dmt->info.major, dmt->info.minor));
		break;

	case DM_DEVICE_REMOVE:
		_rm_dev_node(dmt->dev_name);
		break;
	}

	return 1;

 bad:
	return 0;
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
