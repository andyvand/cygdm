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

#include "lib.h"
#include "libdm-event.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/* Fetch a string off src and duplicate it into *dest. */
/* FIXME: move to seperate module to share with the daemon. */
static const char delimiter = ' ';
static char *fetch_string(char **src)
{
	char *p, *ret;

	if ((p = strchr(*src, delimiter)))
		*p = 0;

	if ((ret = strdup(*src)))
		*src += strlen(ret) + 1;

	if (p)
		*p = delimiter;

	return ret;
}

/* Parse a device message from the daemon. */
static int parse_message(struct daemon_message *msg, char **dso_name,
			 char **device, enum event_type *events)
{
	char *p = msg->msg;

	if ((*dso_name = fetch_string(&p)) &&
	    (*device   = fetch_string(&p))) {
		*events = atoi(p);

		return 0;
	}

	return -ENOMEM;
}

/* Read message from daemon. */
static int daemon_read(struct fifos *fifos, struct daemon_message *msg)
{
	int bytes = 0, ret = 0;
	fd_set fds;

	memset(msg, 0, sizeof(*msg));
	errno = 0;
	while (bytes < sizeof(*msg) && errno != EOF) {
		do {
			/* Watch daemon read FIFO for input. */
			FD_ZERO(&fds);
			FD_SET(fifos->server, &fds);
		} while (select(fifos->server+1, &fds, NULL, NULL, NULL) != 1);

		ret = read(fifos->server, msg, sizeof(*msg) - bytes);
		bytes += ret > 0 ? ret : 0;
	}

	return bytes == sizeof(*msg);
}

/* Write message to daemon. */
static int daemon_write(struct fifos *fifos, struct daemon_message *msg)
{
	int bytes = 0, ret = 0;
	fd_set fds;

	errno = 0;
	while (bytes < sizeof(*msg) && errno != EIO) {
		do {
			/* Watch daemon write FIFO to be ready for output. */
			FD_ZERO(&fds);
			FD_SET(fifos->client, &fds);
		} while (select(fifos->client +1, NULL, &fds, NULL, NULL) != 1);

		ret = write(fifos->client, msg, sizeof(*msg) - bytes);
		bytes += ret > 0 ? ret : 0;
	}

	return bytes == sizeof(*msg);
}

static int daemon_talk(struct fifos *fifos, struct daemon_message *msg,
		       int cmd, char *dso_name, char *device,
		       enum event_type events)
{
	memset(msg, 0, sizeof(*msg));

	/*
	 * Set command and pack the arguments
	 * into ASCII message string.
	 */
	msg->opcode.cmd = cmd;
	snprintf(msg->msg, sizeof(msg->msg), "%s %s %u",
		 dso_name, device, events);

	/*
	 * Write command and message to and
	 * read status return code from daemon.
	 */
	if (!daemon_write(fifos, msg)) {
		stack;
		return -EIO;
	}

	if (!daemon_read(fifos, msg)) {
		stack;
		return -EIO;
	}

	return msg->opcode.status;
}

/* Fork and exec the daemon. */
static int fork_daemon(void)
{
	int ret;
	pid_t pid;

	if (!(pid = fork())) {
		execvp(DAEMON, NULL);
		log_err("Unable to exec daemon at %s\n", DAEMON);
		ret = 0; /* We should never get here. */
	} else if (pid > 0) /* Parent. */
	 	ret = 1;

	return ret;
}


/* Conditionaly start daemon in case it is not already running. */
static int start_daemon(void)
{
        int ret;

	if ((ret = fork_daemon())){
		/* still need to add functions to start daemon properly */
		sleep(5);
	}

        return ret;
}

/* Initialize client. */
static int init_client(struct fifos *fifos)
{
	/* init fifos */
	memset(fifos, 0, sizeof(*fifos));
        fifos->client_path = FIFO_CLIENT;
        fifos->server_path = FIFO_SERVER;

	/* Create fifos */
	if(((mkfifo(fifos->client_path, 0600) == -1) && errno != EEXIST) ||
	   ((mkfifo(fifos->server_path, 0600) == -1) && errno != EEXIST)){
		log_err("%s: Failed to create a fifo.\n", __func__);
                return 0;
	}
	/* do we really need to chmod if they were created with right perms? */
	chmod(fifos->client_path, 0600);
	chmod(fifos->server_path, 0600);

	/* Open the fifo used to read from the daemon. **
	** Allows daemon to create its write fifo..... */
	if((fifos->server = open(fifos->server_path, O_RDONLY | O_NONBLOCK)) < 0){
		log_err("%s: open server fifo %s\n", __func__, fifos->server_path);
		stack;
		return 0;
	}

	/* Lock out anyone else trying to do communication with the daemon */
	if(flock(fifos->server, LOCK_EX) < 0){
		log_err("%s: flock %s\n", __func__, fifos->server_path);
		close(fifos->server);
		return 0;
	}

	/* Anyone listening?  If not, errno will be ENXIO */
	if((fifos->client = open(fifos->client_path, O_WRONLY | O_NONBLOCK)) < 0){
		if(errno != ENXIO){
			log_err("%s: open client fifo %s\n",
				__func__, fifos->client_path);
			close(fifos->server);
			stack;
			return 0;
		}
		
		if(!start_daemon()){
			stack;
			return 0;
		}

		/* Daemon is started, retry the open */
		fifos->client = open(fifos->client_path, O_WRONLY | O_NONBLOCK);
		if(fifos->client < 0){
			log_err("%s: open client fifo %s\n",
				__func__, fifos->client_path);
			close(fifos->server);
			stack;
			return 0;
		}
	}
	
	return 1;
}

static void dtr_client(struct fifos *fifos){
	if (flock(fifos->server, LOCK_UN))
                log_err("flock unlock %s\n", fifos->server_path);
	close(fifos->client);
	close(fifos->server);
}

/* Check, if a device exists. */
static int device_exists(char *device)
{
	int f;

	if ((f = open(device, O_RDONLY)) == -1)
		return 0;

	close(f);

	return 1;
}

/* Handle the event (de)registration call and return negative error codes. */
static int do_event(int cmd, struct daemon_message *msg,
		    char *dso_name, char *device, enum event_type events)
{
	int ret;
	struct fifos fifos;

	if (!init_client(&fifos)) {
		stack;
		return -ESRCH;
	}

	ret = daemon_talk(&fifos, msg, cmd, dso_name, device, events);

	/* what is the opposite of init? */
	dtr_client(&fifos);
	
	return ret;
}

/* External library interface. */
int dm_register_for_event(char *dso_name, char *device, enum event_type events)
{
	struct daemon_message msg;

	if (!device_exists(device))
		return -ENODEV;

	return do_event(CMD_REGISTER_FOR_EVENT, &msg, dso_name, device, events);
}

int dm_unregister_for_event(char *dso_name, char *device,
			   enum event_type events)
{
	struct daemon_message msg;

	if (!device_exists(device))
		return -ENODEV;

	return do_event(CMD_UNREGISTER_FOR_EVENT, &msg, dso_name,
			device, events);
}

int dm_get_registered_device(char **dso_name, char **device,
			     enum event_type *events, int next)
{
	int ret;
	struct daemon_message msg;

	if (!(ret = do_event(next ? CMD_GET_NEXT_REGISTERED_DEVICE :
				    CMD_GET_REGISTERED_DEVICE,
			     &msg, *dso_name, *device, *events)))
		ret = parse_message(&msg, dso_name, device, events);

	return ret;
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
