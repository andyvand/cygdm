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
	struct log_data *data;
};

/* FIXME: probably shouldn't do it this way, but... */
static LIST_INIT(logs);

/* locking for log accesss */
static void* (*init_lock_fn)(void) = NULL;
static int (*lock_fn)(void *) = NULL;
static int (*unlock_fn)(void *) = NULL;
static void (*destroy_lock_fn)(void *) = NULL;
void *lock_dlh = NULL;
void *lock_handle = NULL;

static void *init_lock(void)
{
	return init_lock_fn ? init_lock_fn() : NULL;
}

static int lock_list(void *handle)
{
	if (lock_fn)
		return !(*lock_fn)(handle);
	return 0;
}

static int unlock_list(void *handle)
{
	if (unlock_fn)
		return !(*unlock_fn)(handle);
	return 0;
}

static void destroy_lock(void *handle)
{
	if(destroy_lock_fn)
		(*destroy_lock_fn)(handle);
}

static void *init_nop_lock(void)
{
	return NULL;
}

static int nop_lock(void *handle)
{
	return 0;
}

static int nop_unlock(void *handle)
{
	return 0;
}

static void destroy_nop_lock(void *handle)
{
	return;
}

static int load_lock_syms(struct log_data *data)
{
	void *dlh;

	if (!(dlh = dlopen("libmultilog_pthread_lock.so", RTLD_NOW))) {
		//fprintf(stderr, "%s\n", dlerror());
		if(strstr(dlerror(), "undefined symbol: pthread")) {
			fprintf(stderr, "pthread library not linked in - using nop locking\n");
			init_lock_fn = init_nop_lock;
			lock_fn = nop_lock;
			unlock_fn = nop_unlock;
			destroy_lock_fn = destroy_nop_lock;
			return 1;
		}
		else
			return 0;
	}

	lock_dlh = dlh;

	return ((init_lock_fn = dlsym(dlh, "init_locking")) &&
		(lock_fn = dlsym(dlh, "lock_fn")) &&
		(unlock_fn = dlsym(dlh, "unlock_fn")) &&
		(destroy_lock_fn = dlsym(dlh, "destroy_locking")));
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

	if (!log_fxn || !start_syslog) {
		dlclose(logdata->info.threaded_syslog.dlh);
		return 0;
	}

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

	/* FIXME: Potential race here */
	/* attempt to load locking protocol */
	if(!init_lock_fn) {
		if(!load_lock_syms(data)) {
			fprintf(stderr, "Unalbe to load locking\n");
			return 0;
		}
		lock_handle = init_lock();
	}
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
	lock_list(lock_handle);

	list_iterate_items(ll, &logs) {
		if (ll->type == type) {
			unlock_list(lock_handle);
			free(logl);
			return 1;
		}
	}
	logl->type = type;
	logl->data = data;
	list_add(&logs, &logl->list);
	unlock_list(lock_handle);

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
		if (!start_threaded_syslog(logl, data)) {
			lock_list(lock_handle);
			list_del(&logl->list);
			unlock_list(lock_handle);
			free(logl);
			return 0;
		}

		break;
	case custom:
		/* Caller should use multilog_custom to set their
		 * logging fxn */
		logl->log = nop_log;
		break;
	}

	return 1;
}

/* Resets the logging handle to no logging */
/* FIXME: how does this stop the logging threads ? */
void multilog_clear_logging(void)
{
	struct list *tmp, *next;
	struct log_list *logl;
	struct list ll;

	list_init(&ll);

	/* First step: move elements to temporary local list safely. */
	lock_list(lock_handle);

	list_iterate_safe(tmp, next, &logs) {
		list_del(tmp);
		list_add(&ll, tmp);
	}

	unlock_list(lock_handle);

	/* Second step: delete them. */
	list_iterate_safe(tmp, next, &ll) {
		logl = list_item(tmp, struct log_list);

		if(logl->type == threaded_syslog) {
			if(logl->data->info.threaded_syslog.dlh) {
				int (*stop_syslog) (struct log_data *log);
				stop_syslog = dlsym(logl->data->info.threaded_syslog.dlh,
						    "stop_syslog_thread");
				stop_syslog(logl->data);
				dlclose(logl->data->info.threaded_syslog.dlh);
			}
		}

		if (logl->data)
			free(logl->data);

		list_del(tmp);
	}
	/* FIXME: Not sure the destroy_lock call is really necessary */
	destroy_lock(lock_handle);
	dlclose(lock_dlh);

}

/* FIXME: Might want to have this return an error if we can't find the type */
void multilog_del_type(enum log_type type, struct log_data *data)
{
	struct list *tmp, *next;
	struct log_list *logl, *ll = NULL;

	/* First delete type from list safely. */
	lock_list(lock_handle);

	list_iterate_safe(tmp, next, &logs) {
		logl = list_item(tmp, struct log_list);	

		if (logl->type == type) {
			ll = logl;
			list_del(tmp);
			break;
		}
	}

	unlock_list(lock_handle);

	if (ll) {
		if (ll->type == threaded_syslog) {
			int (*stop_syslog) (struct log_data *log);

			if ((stop_syslog = dlsym(data->info.threaded_syslog.dlh, "stop_syslog_thread")))
				stop_syslog(data);

			dlclose(data->info.threaded_syslog.dlh);
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
	lock_list(lock_handle);

	list_iterate_items(logl, &logs) {
		if (logl->type == custom && logl->log == nop_log)
			logl->log = fn;
	}

	unlock_list(lock_handle);
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

	lock_list(lock_handle);

	list_iterate_items(logl, &logs)
		logl->log(logl->data, priority, file, line, buf);

	unlock_list(lock_handle);
}
