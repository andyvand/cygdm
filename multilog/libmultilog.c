/*
 * Copyright (C) 2005 Red Hat, Inc. All rights reserved.
 *
 * This file is part of the device-mapper userspace tools.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/select.h>
#include "list.h"
#include "libmultilog.h"

#include <unistd.h>

struct log_list {
	struct list list;
	enum log_type type;
	multilog_fn log;
	void *data;
};

/* FIXME: probably shouldn't do it this way, but... */
static LIST_INIT(logs);

/* Noop logging until the custom log fxn gets registered */
static void nop_log(int priority, const char *file, int line,
		    const char *string)
{
	return;
}
static void standard_log(int priority, const char *file, int line,
			 const char *string)
{

/*	switch (priority) {
	case _LOG_*/
	fprintf(stderr, string);
	fputc('\n', stderr);
}

static int start_threaded_syslog(struct log_list *logl, struct log_data *logdata)
{

	if(!(logdata->info.threaded_syslog.dlh = dlopen("libmultilog_async.so", RTLD_NOW))) {
		fprintf(stderr, "%s\n", dlerror());
		return 0;
	}

	void (*log_fxn) (int priority, const char *file, int line,
			 const char *string);
	int (*start_syslog) (pthread_t *t, long usecs);

	log_fxn = dlsym(logdata->info.threaded_syslog.dlh, "write_to_buf");
	start_syslog = dlsym(logdata->info.threaded_syslog.dlh, "start_syslog_thread");

	if(!start_syslog(&(logdata->info.threaded_syslog.thread), 100))
		fprintf(stderr, "Gah\n");
	logl->log = log_fxn;
	return 1;

}

/* FIXME: Can currently add multiple logging types */
int multilog_add_type(enum log_type type, struct log_data *data)
{
	struct log_list *logl;
	struct list *tmp;

	if(!(logl = malloc(sizeof(*logl))))
		return 0;
	if(!(memset(logl, 0, sizeof(*logl))))
		return 0;

	/* If the type has already been registered, it doesn't need to
	 * be registered again */
	list_iterate(tmp, &logs) {
		logl = list_item(tmp, struct log_list);
		if(logl->type == type)
			return 1;
	}

	list_init(&logl->list);
	logl->type = type;
	logl->data = data;

	switch(type) {
	case standard:
		logl->log = standard_log;
		break;
	case logfile:
		/* FIXME: Not implemented yet */
		logl->log = nop_log;
		break;
	case std_syslog:
		/* FIXME: Not implemented yet */
		logl->log = nop_log;
		break;
	case threaded_syslog:
		if(!start_threaded_syslog(logl, data)) {
			return 0;
		}
		break;
	case custom:
		/* Caller should use multilog_custom to set their
		 * logging fxn */
		logl->log = nop_log;
		break;
	}

	list_add(&logs, &logl->list);
	return 1;
}

/* FIXME: Might want to have this return an error if we can't find the type */
void multilog_del_type(enum log_type type, struct log_data *data)
{
	struct list *tmp, *next;
	struct log_list *logl;

	list_iterate_safe(tmp, next, &logs) {
		logl = list_item(tmp, struct log_list);
		if(logl->type == type) {
			if(logl->type == threaded_syslog) {
				int (*stop_syslog) (struct log_data *log);
				stop_syslog = dlsym(data->info.threaded_syslog.dlh,
						    "stop_syslog_thread");
				stop_syslog(data);
			}
			list_del(tmp);
			break;
		}
	}

}

void multilog_custom(multilog_fn fn)
{
	struct list *tmp;
	struct log_list *logl;
	/* FIXME: Should we present an error if we can't find a
	 * suitable target? */
	list_iterate(tmp, &logs) {
		logl = list_item(tmp, struct log_list);
		if(logl->type == custom && logl->log == nop_log)
			logl->log = fn;
	}
}


void multilog(int priority, const char *file, int line, const char *format, ...)
{
	struct list *tmp;
	struct log_list *logl;
	char buf[4096];

	/* If someone trys to write a message and there are no log
	 * types registered, register the standard log type */
	if(list_empty(&logs)) {
		multilog_add_type(standard, NULL);
	}

	va_list args;
	/* FIXME: shove everything into a single string */
	va_start(args, format);

	vsnprintf(buf, 4096, format, args);

	va_end(args);

	list_iterate(tmp, &logs) {
		logl = list_item(tmp, struct log_list);
		logl->log(priority, file, line, buf);
	}

}
