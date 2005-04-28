#include <stdio.h>

#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include "libmultilog.h"

int main(int argc, char **argv)
{
	pthread_t thread;
	int i;

	if(!start_syslog_thread(&thread, 1))
		fprintf(stderr, "Couldn't start syslog thread\n");

	for( i = 0; i < 100; i++) {
		log_err("Testing really long strings so that we can fill the buffer up and show skips %d", i);
	}

	log_debug("Testing debug");


	log_err("Test of errors2");

	sleep(2);

	log_err("Test of errors3");
	log_err("Test of errors4");

	log_err("Test of errors5");
	log_err("Test of errors6");

	pthread_cancel(thread);
	pthread_join(thread, NULL);

	return 0;
}
