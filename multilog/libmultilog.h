
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

/* The #defines here were almost exactly copied from lvm2 */

#define _LOG_DEBUG 7
#define _LOG_INFO 6
#define _LOG_NOTICE 5
#define _LOG_WARN 4
#define _LOG_ERR 3
#define _LOG_FATAL 2


#define plog(p, x...) write_to_buf(p, __FILE__, __func__, __LINE__, ## x)

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


int write_to_buf(int priority, const char *file, const char *func, int line,
		 const char *format, ...)
                 __attribute__ ((format(printf, 5, 6)));

int start_syslog_thread(pthread_t *thread, long usecs);

#endif
