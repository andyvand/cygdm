
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

#ifndef LIB_MULTILOG_H
#define LIB_MULTILOG_H

#include <sys/types.h>
/* The code here was almost exactly copied from lvm2 &device-mapper */

#define _LOG_DEBUG 7
#define _LOG_INFO 6
#define _LOG_NOTICE 5
#define _LOG_WARN 4
#define _LOG_ERR 3
#define _LOG_FATAL 2


struct file_log {
	const char *filename;
};

struct threaded_syslog_log {
	pthread_t thread;
	void *dlh;
};

union log_info {
	struct file_log logfile;
	struct threaded_syslog_log threaded_syslog;
	void *custom;
};

struct log_data {
	int verbose_level;
	union log_info info;
};

enum log_type {
	standard,
	logfile,
	std_syslog,
	threaded_syslog,
	custom,
};

typedef void (*multilog_fn) (void *data, int level, const char *file, int line,
			     const char *f);

void multilog(int priority, const char *file, int line, const char *f, ...)
	__attribute__ ((format(printf, 4, 5)));

/*
 * The library user may wish to register their own
 * logging function, by default errors go to stderr.
 * Use dm_log_init(NULL) to restore the default log fn.
 */
int multilog_add_type(enum log_type type, struct log_data *data);
void multilog_clear_logging(void);
void multilog_del_type(enum log_type type, struct log_data *data);
void multilog_custom(multilog_fn fn);
void multilog_init_verbose(int level);

#undef plog
#undef log_error
#undef log_print
#undef log_verbose
#undef log_very_verbose

#define plog(p, x...) multilog(p, __FILE__, __LINE__, ## x)

#define log_debug(x...) plog(_LOG_DEBUG, x)
#define log_info(x...) plog(_LOG_INFO, x)
#define log_notice(x...) plog(_LOG_NOTICE, x)
#define log_warn(x...) plog(_LOG_WARN, x)
#define log_err(x...) plog(_LOG_ERR, x)
#define log_fatal(x...) plog(_LOG_FATAL, x)

#define stack log_debug("<backtrace>")	/* Backtrace on error */

#define log_error(args...) log_err(args)
#define log_print(args...) log_warn(args)
#define log_verbose(args...) log_notice(args)
#define log_very_verbose(args...) log_info(args)

int start_syslog_thread(pthread_t *thread, long usecs);

#endif
