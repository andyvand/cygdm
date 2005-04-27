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

/* FIXME Replace with log.h */
#undef log_print
#undef log_err
#undef stack
#define log_print(x...)	   fprintf(stderr, "[dmeventdlib] " x)
#define log_err(x...)	   log_print(x)
#define stack log_print("trace: %s:%s(%d)\n", __FILE__, __func__, __LINE__);


/* Initialize the fifos structure. */
static void init_fifos(struct fifos *fifos)
{
	memset(fifos, 0, sizeof(*fifos));
	fifos->client_path = FIFO_CLIENT;
	fifos->server_path = FIFO_SERVER;
}

static int create_fifo(char *path, char *what)
{
	if (mkfifo(path, 0600) == -1 && errno != EEXIST) {
		log_err("%s: create %s fifo %s\n", __func__, what, path);
		return 0;
	}

	chmod(path, 0600);

	return 1;
}

static int create_fifos(struct fifos *fifos)
{
	if (!create_fifo(fifos->client_path, "client")) {
		stack;
		return 0;
	}

	if (!create_fifo(fifos->server_path, "server")) {
		stack;
		return 0;
	}

	return 1;
}

static int open_fifo(char *path, int rw, char *what)
{
	int ret;

        if ((ret = open(path, rw)) == -1)
		log_err("%s: open %s fifo %s\n", __func__, what, path);

	return ret;
}

static int open_fifos(struct fifos *fifos)
{
	/* blocks until daemon is ready to write */
        if ((fifos->server = open_fifo(fifos->server_path, O_RDONLY,
				       "server")) == -1) {
		stack;
		return 0;
	}

	/* blocks until daemon is ready to read */
	if ((fifos->client = open_fifo(fifos->client_path, O_WRONLY,
				       "client")) == -1) {
		stack;
		close(fifos->server);
		return 0;
	}

	return 1;
}

/*
 * flock file.
 *
 * Used to synchronize daemon startups and serialize daemon communication.
 */
static int lf = -1; /* FIXME Unused! */

static int _lock(char *file, int *lf2)
{
	/* Already locked. */
	if (*lf2 > -1)
		return 1;

	if ((*lf2 = open(file, O_CREAT | O_RDWR, 0644)) == -1) {
		log_err("Unable to open lockfile\n");
		return 0;
	}

	if (flock(*lf2, LOCK_EX | LOCK_NB) == -1) {
		log_err("%s: flock %s\n", __func__, file);
		close(*lf2);
		*lf2 = -1;
		return 0;
	}

	return 1;
}

/* Unlock file. */
static void _unlock(char *file, int *lf2)
{
	/* Not locked! */
	if (*lf2 == -1)
		return;

	unlink(file);
	if (flock(*lf2, LOCK_UN))
		log_err("flock unlock %s\n", file);

	if (close(*lf2))
		log_err("close %s\n", file);

	*lf2 = -1;
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

	do {
		/* Watch daemon write FIFO to be ready for output. */
		FD_ZERO(&fds);
		FD_SET(fifos->client, &fds);
	} while (select(fifos->client + 1, NULL, &fds, NULL, NULL) <= 0);

	while (bytes < sizeof(*msg) && errno != EIO) {
		ret = write(fifos->client, msg, sizeof(*msg) - bytes);
		bytes += ret > 0 ? ret : 0;
	}

	return bytes == sizeof(*msg);
}

static int daemon_talk(struct fifos *fifos, int cmd,
		       char *dso_name, char *device, enum event_type events)
{
	struct daemon_message msg;

	if (!_lock(LOCKFILE, &lf)) {
		stack;
		return -EPERM;
	}

	memset(&msg, 0, sizeof(msg));

	/*
	 * Set command and pack the arguments
	 * into ASCII message string.
	 */
	msg.opcode.cmd = cmd;
	snprintf(msg.msg, sizeof(msg.msg), "%s %s %u",
		 dso_name, device, events);

	/*
	 * Write command and message to and
	 * read status return code from daemon.
	 */
	if (!daemon_write(fifos, &msg)) {
		stack;
		return -EIO;
	}

	if (!daemon_read(fifos, &msg)) {
		stack;
		return -EIO;
	}

	_unlock(LOCKFILE, &lf);

	return msg.opcode.status;
}

/* Fork and exec the daemon. */
static int fork_daemon(struct fifos *fifos)
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

/* Wait for daemon to startup. */
static int pf = -1;
static int daemon_startup(void)
{
	int ret, retry = 10;

	while (retry-- && (ret = _lock(PIDFILE, &pf))) {
		_unlock(PIDFILE, &pf);
		sleep(1);
	}

	return !ret;
}

/* Conditionaly start daemon in case it is not already running. */
static int start_daemon(struct fifos *fifos)
{
	int ret;

	/*
	 * Take a lock out on the lock file avoiding races, so
	 * that only one caller to fork the daemon is possible.
	 *
	 * Take an flock out on the pidfile to check
	 * that the daemon is running. If not -> start it.
	 */
	if ((ret = _lock(LOCKFILE, &lf))) {
		/* Check if daemon is active. */
		if ((ret = _lock(PIDFILE, &pf))) {
			_unlock(PIDFILE, &pf);
			if ((ret = fork_daemon(fifos)))
				ret = daemon_startup();
			else
				stack;
		} else
			ret = 1; /* Daemon already running -> ok. */

		_unlock(LOCKFILE, &lf);
	}

	return ret;
}

/* Initialize client. */
static int init_client(struct fifos *fifos)
{
	init_fifos(fifos);

	/* Check/create fifos, optionally start daemon and open fifos. */
	if (!create_fifos(fifos)) {
		stack;
		return 0;
	}

	if (!start_daemon(fifos)) {
		stack;
		return 0;
	}

	if (!open_fifos(fifos)) {
		stack;
		return 0;
	}

	return 1;
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
static int do_event(int cmd, char *dso_name, char *device,
		    enum event_type events)
{
	int ret;
	struct fifos fifos;

	if (!device_exists(device))
		return -ENODEV;

	if (!init_client(&fifos)) {
		stack;
		return -ESRCH;
	}

	if ((ret = daemon_talk(&fifos, cmd, dso_name, device, events)) < 0)
		stack;

	return ret;
}

/* External library interface. */
int dm_register_for_event(char *dso_name, char *device, enum event_type events)
{
	return do_event(CMD_REGISTER_FOR_EVENT, dso_name, device, events);
}

int dm_unregister_for_event(char *dso_name, char *device, uint32_t events)
{
	return do_event(CMD_UNREGISTER_FOR_EVENT, dso_name, device, events);
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
