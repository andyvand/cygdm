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
#include "libdevmapper-event.h"
//#include "libmultilog.h"
#include "dmeventd.h"

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
#include <sys/wait.h>
#include <arpa/inet.h>		/* for htonl, ntohl */

struct dm_event_handler {
	const char *dso;

	const char *dev_name;

	const char *uuid;
	int major;
	int minor;

	enum dm_event_mask mask;
};

static void dm_event_handler_clear_dev_name(struct dm_event_handler *dmevh)
{
	dmevh->dev_name = dmevh->uuid = NULL;
	dmevh->major = dmevh->minor = 0;
}

struct dm_event_handler *dm_event_handler_create(void)
{
	struct dm_event_handler *dmevh = NULL;

	if (!(dmevh = dm_malloc(sizeof(*dmevh))))
		return NULL;

	dmevh->dso = dmevh->dev_name = dmevh->uuid = NULL;
	dmevh->major = dmevh->minor = 0;
	dmevh->mask = 0;

	return dmevh;
}

void dm_event_handler_destroy(struct dm_event_handler *dmevh)
{
	dm_free(dmevh);
}

void dm_event_handler_set_dso(struct dm_event_handler *dmevh, const char *path)
{
	dmevh->dso = path;
}

void dm_event_handler_set_dev_name(struct dm_event_handler *dmevh, const char *dev_name)
{
	dm_event_handler_clear_dev_name(dmevh);

	dmevh->dev_name = dev_name;
}

void dm_event_handler_set_uuid(struct dm_event_handler *dmevh, const char *uuid)
{
	dm_event_handler_clear_dev_name(dmevh);

	dmevh->uuid = uuid;
}

void dm_event_handler_set_major(struct dm_event_handler *dmevh, int major)
{
	int minor = dmevh->minor;

	dm_event_handler_clear_dev_name(dmevh);

	dmevh->major = major;
	dmevh->minor = minor;
}

void dm_event_handler_set_minor(struct dm_event_handler *dmevh, int minor)
{
	int major = dmevh->major;

	dm_event_handler_clear_dev_name(dmevh);

	dmevh->major = major;
	dmevh->minor = minor;
}

void dm_event_handler_set_event_mask(struct dm_event_handler *dmevh,
				     enum dm_event_mask evmask)
{
	dmevh->mask = evmask;
}

const char *dm_event_handler_get_dso(const struct dm_event_handler *dmevh)
{
	return dmevh->dso;
}

const char *dm_event_handler_get_dev_name(const struct dm_event_handler *dmevh)
{
	return dmevh->dev_name;
}

const char *dm_event_handler_get_uuid(const struct dm_event_handler *dmevh)
{
	return dmevh->uuid;
}

int dm_event_handler_get_major(const struct dm_event_handler *dmevh)
{
	return dmevh->major;
}

int dm_event_handler_get_minor(const struct dm_event_handler *dmevh)
{
	return dmevh->minor;
}

enum dm_event_mask dm_event_handler_get_event_mask(const struct dm_event_handler *dmevh)
{
	return dmevh->mask;
}

/*
 * daemon_read
 * @fifos
 * @msg
 *
 * Read message from daemon.
 *
 * Returns: 0 on failure, 1 on success
 */
static int _daemon_read(struct dm_event_fifos *fifos,
			struct dm_event_daemon_message *msg)
{
	unsigned bytes = 0;
	int ret, i;
	fd_set fds;
	struct timeval tval = { 0, 0 };
	size_t size = 2 * sizeof(uint32_t);	/* status + size */
	char *buf = alloca(size);
	int header = 1;

	while (bytes < size) {
		for (i = 0, ret = 0; (i < 20) && (ret < 1); i++) {
			/* Watch daemon read FIFO for input. */
			FD_ZERO(&fds);
			FD_SET(fifos->server, &fds);
			tval.tv_sec = 1;
			ret = select(fifos->server + 1, &fds, NULL, NULL,
				     &tval);
			if (ret < 0 && errno != EINTR) {
				log_error("Unable to read from event server");
				return 0;
			}
		}
		if (ret < 1) {
			log_error("Unable to read from event server.");
			return 0;
		}

		ret = read(fifos->server, buf + bytes, size);
		if (ret < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			else {
				log_error("Unable to read from event server.");
				return 0;
			}
		}

		bytes += ret;
		if (bytes == 2 * sizeof(uint32_t) && header) {
			msg->cmd = ntohl(*((uint32_t *)buf));
			msg->size = ntohl(*((uint32_t *)buf + 1));
			buf = msg->data = dm_malloc(msg->size);
			size = msg->size;
			bytes = 0;
			header = 0;
		}
	}

	if (bytes != size) {
		if (msg->data)
			dm_free(msg->data);
		msg->data = NULL;
	}

	return bytes == size;
}

/* Write message to daemon. */
static int _daemon_write(struct dm_event_fifos *fifos,
			 struct dm_event_daemon_message *msg)
{
	unsigned bytes = 0;
	int ret = 0;
	fd_set fds;

	size_t size = 2 * sizeof(uint32_t) + msg->size;
	char *buf = alloca(size);

	*((uint32_t *)buf) = htonl(msg->cmd);
	*((uint32_t *)buf + 1) = htonl(msg->size);
	memcpy(buf + 2 * sizeof(uint32_t), msg->data, msg->size);

	while (bytes < size) {
		do {
			/* Watch daemon write FIFO to be ready for output. */
			FD_ZERO(&fds);
			FD_SET(fifos->client, &fds);
			ret = select(fifos->client + 1, NULL, &fds, NULL, NULL);
			if ((ret < 0) && (errno != EINTR)) {
				log_error("Unable to talk to event daemon");
				return 0;
			}
		} while (ret < 1);

		ret = write(fifos->client, ((char *) buf) + bytes,
			    size - bytes);
		if (ret < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			else {
				log_error("Unable to talk to event daemon");
				return 0;
			}
		}

		bytes += ret;
	}

	return bytes == size;
}

static int _daemon_talk(struct dm_event_fifos *fifos,
			struct dm_event_daemon_message *msg, int cmd,
			const char *dso_name, const char *dev_name,
			enum dm_event_mask evmask, uint32_t timeout)
{
	const char *dso = dso_name ? dso_name : "";
	const char *dev = dev_name ? dev_name : "";
	const char *fmt = "%s %s %u %" PRIu32;
	int msg_size;
	memset(msg, 0, sizeof(*msg));

	/*
	 * Set command and pack the arguments
	 * into ASCII message string.
	 */
	msg->cmd = cmd;
	if ((msg_size = dm_asprintf(&(msg->data), fmt, dso, dev, evmask,
				     timeout)) < 0) {
		log_error("_daemon_talk: message allocation failed");
		return -ENOMEM;
	}
	msg->size = msg_size;

	/*
	 * Write command and message to and
	 * read status return code from daemon.
	 */
	if (!_daemon_write(fifos, msg)) {
		stack;
		return -EIO;
	}

	if (!_daemon_read(fifos, msg)) {
		stack;
		return -EIO;
	}

	return (int32_t) msg->cmd;
}

/*
 * start_daemon
 *
 * This function forks off a process (dmeventd) that will handle
 * the events.  I am currently test opening one of the fifos to
 * ensure that the daemon is running and listening...  I thought
 * this would be less expensive than fork/exec'ing every time.
 * Perhaps there is an even quicker/better way (no, checking the
 * lock file is _not_ a better way).
 *
 * Returns: 1 on success, 0 otherwise
 */
static int _start_daemon(struct dm_event_fifos *fifos)
{
	int pid, ret = 0;
	int status;
	struct stat statbuf;

	if (stat(fifos->client_path, &statbuf))
		goto start_server;

	if (!S_ISFIFO(statbuf.st_mode)) {
		log_error("%s is not a fifo.", fifos->client_path);
		return 0;
	}

	/* Anyone listening?  If not, errno will be ENXIO */
	fifos->client = open(fifos->client_path, O_WRONLY | O_NONBLOCK);
	if (fifos->client >= 0) {
		/* server is running and listening */

		close(fifos->client);
		return 1;
	} else if (errno != ENXIO) {
		/* problem */

		log_error("%s: Can't open client fifo %s: %s",
			  __func__, fifos->client_path, strerror(errno));
		stack;
		return 0;
	}

      start_server:
	/* server is not running */
	pid = fork();

	if (pid < 0)
		log_error("Unable to fork.");

	else if (!pid) {
		execvp(DMEVENTD_PATH, NULL);
		exit(EXIT_FAILURE);
	} else {
		if (waitpid(pid, &status, 0) < 0)
			log_error("Unable to start dmeventd: %s",
				  strerror(errno));
		else if (WEXITSTATUS(status))
			log_error("Unable to start dmeventd.");
		else
			ret = 1;
	}

	return ret;
}

/* Initialize client. */
static int _init_client(struct dm_event_fifos *fifos)
{
	/* FIXME? Is fifo the most suitable method? Why not share
	   comms/daemon code with something else e.g. multipath? */

	/* init fifos */
	memset(fifos, 0, sizeof(*fifos));
	fifos->client_path = DM_EVENT_FIFO_CLIENT;
	fifos->server_path = DM_EVENT_FIFO_SERVER;

	if (!_start_daemon(fifos)) {
		stack;
		return 0;
	}

	/* Open the fifo used to read from the daemon. */
	if ((fifos->server = open(fifos->server_path, O_RDWR)) < 0) {
		log_error("%s: open server fifo %s",
			  __func__, fifos->server_path);
		stack;
		return 0;
	}

	/* Lock out anyone else trying to do communication with the daemon. */
	if (flock(fifos->server, LOCK_EX) < 0) {
		log_error("%s: flock %s", __func__, fifos->server_path);
		close(fifos->server);
		return 0;
	}

/*	if ((fifos->client = open(fifos->client_path, O_WRONLY | O_NONBLOCK)) < 0) {*/
	if ((fifos->client = open(fifos->client_path, O_RDWR | O_NONBLOCK)) < 0) {
		log_error("%s: Can't open client fifo %s: %s",
			  __func__, fifos->client_path, strerror(errno));
		close(fifos->server);
		stack;
		return 0;
	}

	return 1;
}

static void _dtr_client(struct dm_event_fifos *fifos)
{
	if (flock(fifos->server, LOCK_UN))
		log_error("flock unlock %s", fifos->server_path);

	close(fifos->client);
	close(fifos->server);
}

/* Get uuid of a device */
static struct dm_task *_get_device_info(const struct dm_event_handler *dmevh)
{
	struct dm_task *dmt;
	struct dm_info info;

	if (!(dmt = dm_task_create(DM_DEVICE_INFO))) {
		log_error("_get_device_info: dm_task creation for info failed");
		return NULL;
	}

	if (dmevh->uuid)
		dm_task_set_uuid(dmt, dmevh->uuid);
	else if (dmevh->dev_name)
		dm_task_set_name(dmt, dmevh->dev_name);
	else if (dmevh->major && dmevh->minor) {
		dm_task_set_major(dmt, dmevh->major);
		dm_task_set_minor(dmt, dmevh->minor);
        }

	/* FIXME Add name or uuid or devno to messages */
	if (!dm_task_run(dmt)) {
		log_error("_get_device_info: dm_task_run() failed");
		goto failed;
	}

	if (!dm_task_get_info(dmt, &info)) {
		log_error("_get_device_info: failed to get info for device");
		goto failed;
	}

	if (!info.exists) {
		log_error("_get_device_info: device not found");
		goto failed;
	}

	return dmt;

failed:
	dm_task_destroy(dmt);
	return NULL;
}

/* Handle the event (de)registration call and return negative error codes. */
static int _do_event(int cmd, struct dm_event_daemon_message *msg,
		    const char *dso_name, const char *dev_name,
		    enum dm_event_mask evmask, uint32_t timeout)
{
	int ret;
	struct dm_event_fifos fifos;

	if (!_init_client(&fifos)) {
		stack;
		return -ESRCH;
	}

	ret = _daemon_talk(&fifos, msg, cmd, dso_name, dev_name, evmask, timeout);

	/* what is the opposite of init? */
	_dtr_client(&fifos);

	return ret;
}

/* External library interface. */
int dm_event_register_handler(const struct dm_event_handler *dmevh)
{
	int ret = 1, err;
	const char *uuid;
	struct dm_task *dmt;
	struct dm_event_daemon_message msg;

	if (!(dmt = _get_device_info(dmevh))) {
		stack;
		return 0;
	}

	uuid = dm_task_get_uuid(dmt);

	if ((err = _do_event(DM_EVENT_CMD_REGISTER_FOR_EVENT, &msg,
			     dmevh->dso, uuid, dmevh->mask, 0)) < 0) {
		log_error("%s: event registration failed: %s",
			  dm_task_get_name(dmt),
			  msg.data ? msg.data : strerror(-err));
		ret = 0;
	}

	if (msg.data)
		dm_free(msg.data);

	dm_task_destroy(dmt);

	return ret;
}

int dm_event_unregister_handler(const struct dm_event_handler *dmevh)
{
	int ret = 1, err;
	const char *uuid;
	struct dm_task *dmt;
	struct dm_event_daemon_message msg;

	if (!(dmt = _get_device_info(dmevh))) {
		stack;
		return 0;
	}

	uuid = dm_task_get_uuid(dmt);

	if ((err = _do_event(DM_EVENT_CMD_UNREGISTER_FOR_EVENT, &msg,
			    dmevh->dso, uuid, dmevh->mask, 0)) < 0) {
		log_error("%s: event deregistration failed: %s",
			  dm_task_get_name(dmt),
			  msg.data ? msg.data : strerror(-err));
		ret = 0;
	}

	if (msg.data)
		dm_free(msg.data);

	dm_task_destroy(dmt);

	return ret;
}

/* Fetch a string off src and duplicate it into *dest. */
/* FIXME: move to separate module to share with the daemon. */
static char *_fetch_string(char **src, const int delimiter)
{
	char *p, *ret;

	if ((p = strchr(*src, delimiter)))
		*p = 0;

	if ((ret = dm_strdup(*src)))
		*src += strlen(ret) + 1;

	if (p)
		*p = delimiter;

	return ret;
}

/* Parse a device message from the daemon. */
static int _parse_message(struct dm_event_daemon_message *msg, char **dso_name,
			 char **dev_name, enum dm_event_mask *evmask)
{
	char *p = msg->data;

	if ((*dso_name = _fetch_string(&p, ' ')) &&
	    (*dev_name = _fetch_string(&p, ' '))) {
		*evmask = atoi(p);

		return 0;
	}

	return -ENOMEM;
}

/*
 * dm_event_get_registered_device
 * @dso_name
 * @device_path
 * @mask
 * @next
 *
 * FIXME: This function sucks.
 *
 * Returns: 1 if device found, 0 otherwise (even on error)
 */
int dm_event_get_registered_device(char **dso_name, char **device_path,
				   enum dm_event_mask *mask, int next)
{
	int ret;
	char *dso_name_arg = NULL, *device_path_arg = NULL;
	struct dm_event_daemon_message msg;

	if (!(ret = _do_event(next ? DM_EVENT_CMD_GET_NEXT_REGISTERED_DEVICE :
			     DM_EVENT_CMD_GET_REGISTERED_DEVICE,
			     &msg, *dso_name, *device_path, *mask, 0))) {
		ret = !_parse_message(&msg, &dso_name_arg, &device_path_arg,
				     mask);
	} else			/* FIXME: Make sure this is ENOENT */
		ret = 0;

	if (msg.data)
		dm_free(msg.data);

	if (next) {
		if (*dso_name)
			dm_free(*dso_name);
		if (*device_path)
			dm_free(*device_path);
		*dso_name = dso_name_arg;
		*device_path = device_path_arg;
	} else {
		if (!(*dso_name))
			*dso_name = dso_name_arg;
		if (!(*device_path))
			*device_path = device_path_arg;
	}

	return ret;
}

#if 0				/* left out for now */

int dm_event_set_timeout(const char *device_path, uint32_t timeout)
{
	struct dm_event_daemon_message msg;

	if (!device_exists(device_path))
		return -ENODEV;
	return _do_event(DM_EVENT_CMD_SET_TIMEOUT, &msg,
			NULL, device_path, 0, timeout);
}

int dm_event_get_timeout(const char *device_path, uint32_t *timeout)
{
	int ret;
	struct dm_event_daemon_message msg;

	if (!device_exists(device_path))
		return -ENODEV;
	if (!(ret = _do_event(DM_EVENT_CMD_GET_TIMEOUT, &msg, NULL, device_path,
			     0, 0)))
		*timeout = atoi(msg.data);
	if (msg.data)
		dm_free(msg.data);
	return ret;
}
#endif
