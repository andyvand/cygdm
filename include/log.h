/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 *
 * This file is released under the LGPL.
 */

#ifndef LIB_DMLOG_H
#define LIB_DMLOG_H

#include "libdevmapper.h"

#define _LOG_DEBUG 7
#define _LOG_INFO 6
#define _LOG_NOTICE 5
#define _LOG_WARN 4
#define _LOG_ERR 3
#define _LOG_FATAL 2

extern dm_log_fn _log;

#define plog(l, x...) _log(l, __FILE__, __LINE__, ## x)

#define log_error(x...) plog(_LOG_ERR, x)
#define log_print(x...) plog(_LOG_WARN, x)
#define log_verbose(x...) plog(_LOG_NOTICE, x)
#define log_very_verbose(x...) plog(_LOG_INFO, x)
#define log_debug(x...) plog(_LOG_DEBUG, x)

#endif
