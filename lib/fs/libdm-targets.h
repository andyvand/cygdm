/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

struct target {
	char *str;
	struct target *next;
};

struct dm_task {
	int type;
	char *dev_name;
	int minor;

	struct target *head, *tail;

	struct dm_info info;
};

