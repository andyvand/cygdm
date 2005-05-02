#include <stdio.h>

#include <syslog.h>
#include <unistd.h>
#include "libmultilog.h"

int main(int argc, char **argv)
{
	int i;
	struct threaded_syslog_log sl_logdata;

	sl_logdata.verbose_level = 4;

	if(!multilog_add_type(threaded_syslog, &sl_logdata)) {
		fprintf(stderr, "Unable to add threaded syslog logging\n");
	}
	multilog_add_type(standard, NULL);

	for( i = 0; i < 100; i++) {
		log_err("Testing really long strings so that we can fill the buffer up and show skips %d", i);
		if(i == 5) {
			multilog_del_type(standard, NULL);
		}
	}

	log_debug("Testing debug");

	log_err("Test of errors2");

	sleep(2);

	log_err("Test of errors3");
	log_err("Test of errors4");

	multilog_add_type(standard, NULL);

	log_err("Test of errors5");
	log_err("Test of errors6");

	multilog_del_type(threaded_syslog, &sl_logdata);

	return 0;
}
