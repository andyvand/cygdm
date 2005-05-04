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

/* FIXME: add locking while updating logs registry. */

struct log_list {
	struct list list;
	enum log_type type;
	multilog_fn log;
	void *data;
};

/* FIXME: probably shouldn't do it this way, but... */
static LIST_INIT(logs);

/* Mutext for logs accesses. */
static void *mutex = NULL;
static void lock_mutex(void)
{
}

static void unlock_mutex(void)
{
}

/* Noop logging until the custom log fxn gets registered */
static void nop_log(void *data, int priority, const char *file, int line,
		    const char *string)
{
	return;
}

static void standard_log(void *data, int priority, const char *file, int line,
			 const char *string)
{
	struct log_data *ldata = (struct log_data *) data;
	/* FIXME: stack allocation of large buffer. */
	char locn[512];

	if (ldata->verbose_level > _LOG_DEBUG)
		snprintf(locn, sizeof(locn), "#%s:%d ", file, line);
	else
		locn[0] = '\0';

	switch (ldata->verbose_level) {
	case _LOG_DEBUG:
		if (strcmp("<backtrace>", string) &&
		    ldata->verbose_level >= _LOG_DEBUG)
			fprintf(stderr, "%s%s\n", locn, string);

		break;
	case _LOG_INFO:
		if (ldata->verbose_level >= _LOG_INFO)
			fprintf(stderr, "%s%s\n", locn, string);

		break;
	case _LOG_NOTICE:
		if (ldata->verbose_level >= _LOG_NOTICE)
			fprintf(stderr, "%s%s\n", locn, string);

		break;
	case _LOG_WARN:
		if (ldata->verbose_level >= _LOG_WARN)
			printf("%s\n", string);

		break;
	case _LOG_ERR:
		if (ldata->verbose_level >= _LOG_ERR)
			fprintf(stderr, "%s%s\n", locn, string);

		break;
	case _LOG_FATAL:
	default:
		if (ldata->verbose_level >= _LOG_FATAL)
			fprintf(stderr, "%s%s\n", locn, string);

		break;
	};
}

static int start_threaded_syslog(struct log_list *logl,
				 struct log_data *logdata)
{
	void (*log_fxn) (void *data, int priority, const char *file, int line,
			 const char *string);
	int (*start_syslog) (pthread_t *t, long usecs);

	if (!(logdata->info.threaded_syslog.dlh = dlopen("libmultilog_async.so", RTLD_NOW))) {
		fprintf(stderr, "%s\n", dlerror());
		return 0;
	}

	log_fxn = dlsym(logdata->info.threaded_syslog.dlh, "write_to_buf");
	start_syslog = dlsym(logdata->info.threaded_syslog.dlh, "start_syslog_thread");

	/* FIXME: the timeout here probably can be tweaked */
	/* FIXME: Probably want to do something if this fails */
	if (start_syslog(&(logdata->info.threaded_syslog.thread), 100000))
		logl->log = log_fxn;

	return logl->log ? 1 : 0;
}

/* FIXME: Can currently add multiple logging types. */
int multilog_add_type(enum log_type type, struct log_data *data)
{
	struct log_list *logl, *ll;

	/*
	 * Preallocate because we don't want to sleep holding a lock.
	 */
	if (!(logl = malloc(sizeof(*logl))) ||
	    !(memset(logl, 0, sizeof(*logl))))
		return 0;

	/*
	 * If the type has already been registered,
	 * it doesn't need to be registered again.
	 */
	lock_mutex();

	list_iterate_items(ll, &logs) {
		if (ll->type == type) {
			unlock_mutex();
			free(logl);

			return 1;
		}
	}

	list_init(&logl->list); /* Superfluous but safe ;) */
	logl->type = type;
	logl->data = data;

	switch (type) {
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
		if (!start_threaded_syslog(logl, data))
			return 0;

		break;
	case custom:
		/* Caller should use multilog_custom to set their
		 * logging fxn */
		logl->log = nop_log;
		break;
	}

	list_add(&logs, &logl->list);
	unlock_mutex();

	return 1;
}

/* Resets the logging handle to no logging */
/* FIXME: how does this stop the logging threads ? */
void multilog_clear_logging(void)
{
	struct list *tmp, *next;
	struct log_list *logl;

	list_iterate_safe(tmp, next, &logs) {
		logl = list_item(tmp, struct log_list);

		if (logl->data)
			free(logl->data);

		list_del(tmp);
	}
}

/* FIXME: Might want to have this return an error if we can't find the type */
void multilog_del_type(enum log_type type, struct log_data *data)
{
	struct list *tmp, *next;
	struct log_list *logl, *ll = NULL;

	/* First delete type from list safely. */
	lock_mutex();

	list_iterate_safe(tmp, next, &logs) {
		logl = list_item(tmp, struct log_list);	

		if (logl->type == type) {
			ll = logl;
			list_del(tmp);
			break;
		}
	}

	unlock_mutex();

	if (ll) {
		if (ll->type == threaded_syslog) {
			int (*stop_syslog) (struct log_data *log);

			if ((stop_syslog = dlsym(data->info.threaded_syslog.dlh, "stop_syslog_thread")))
				stop_syslog(data);
		}

		free(ll);
	}
}

void multilog_custom(multilog_fn fn)
{
	struct log_list *logl;

	/*
	 * FIXME: Should we present an error if
	 * we can't find a suitable target?
	 */
	lock_mutex();

	list_iterate_items(logl, &logs) {
		if (logl->type == custom && logl->log == nop_log)
			logl->log = fn;
	}

	unlock_mutex();
}


void multilog(int priority, const char *file, int line, const char *format, ...)
{
	/* FIXME: stack allocation of large buffer. */
	char buf[4096];
	struct log_list *logl;

	va_list args;
	/* FIXME: shove everything into a single string */
	va_start(args, format);
	vsnprintf(buf, 4096, format, args);
	va_end(args);

	lock_mutex();

	list_iterate_items(logl, &logs)
		logl->log(logl->data, priority, file, line, buf);

	unlock_mutex();
}
