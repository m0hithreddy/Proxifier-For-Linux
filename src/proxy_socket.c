/* Essential socket managment functions.

Copyright (C) 2020  Mohith Reddy

Proxifier is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proxifier is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "proxy_socket.h"
#include "proxy.h"
#include "proxy_structures.h"
#include "proxy_functions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

struct proxy_client* ai_flags_sockfd_socktype_create_proxy_client(const char* hostname, const char* port, \
		struct proxy_options* px_opt, int ai_flags, int sockfd, int socktype) {

	struct proxy_client* px_client = (struct proxy_client*) calloc(1, sizeof(struct proxy_client));

	/* Other end Host-Name */

	if (hostname != NULL)
		px_client->hostname = strdup(hostname);

	/* Other end service port */

	if (port != NULL)
		px_client->port = strdup(port);

	/* Standard IPv4 TCP socket options */

	px_client->family = AF_INET;
	px_client->type = socktype;
	px_client->protocol = 0;

	/* Set getaddrinfo() flags */

	px_client->ai_flags = ai_flags;

	/* Network variables */

	px_client->io_timeout = px_opt->io_timeout;

	/* Synchronization variables */

	px_client->sigmask = memndup(px_opt->sigmask, sizeof(sigset_t));

	/* Results */

	px_client->sockfd = sockfd;
	px_client->hostip = NULL;

	return px_client;
}

int init_proxy_client(struct proxy_client* px_client)
{
	int return_status = PROXY_ERROR_NONE;

	if (px_client == NULL)	{
		return_status = PROXY_ERROR_INVAL;
		goto init_error;
	}

	struct addrinfo hints, *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));   // Set the hints as caller requested
	hints.ai_family = px_client->family;
	hints.ai_socktype = px_client->type;
	hints.ai_flags = px_client->ai_flags;
	hints.ai_protocol = px_client->protocol;

	int s = getaddrinfo(px_client->hostname, px_client->port, &hints, &result);   // Call getaddrinfo
	if (s != 0)	{
		return_status = PROXY_ERROR_DNS;
		goto init_error;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		px_client->sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (px_client->sockfd == -1)
			goto next;

		/* If AI_PASSIVE is set, setup the socket for accept() routine else TCP Connect */

		if ((px_client->ai_flags & AI_PASSIVE) || px_client->type == SOCK_DGRAM) {
			/* Bind to address */

			if (bind(px_client->sockfd, rp->ai_addr, rp->ai_addrlen) != 0)
				goto next;

			/* Get the port to which socket binded */

			struct sockaddr_storage sock_res; int sock_len = sizeof(struct sockaddr_storage);

			if (getsockname(px_client->sockfd, (struct sockaddr*) &sock_res, &sock_len) != 0)
				goto next;

			px_client->port = (char*) malloc(sizeof(char) * 6);  // Max port value 65535

			snprintf(px_client->port, 6, "%d", htons((rp->ai_family == AF_INET) ? \
					((struct sockaddr_in*) &sock_res)->sin_port : ((struct sockaddr_in6*) &sock_res)->sin6_port));

			if (px_client->type == SOCK_STREAM) {
				/* Put the socket in passive mode */

				if (listen(px_client->sockfd, PROXY_DEFAULT_ACCEPT_BACKLOG) != 0)
					goto next;
			}

			goto success;
		}
		else {
			/* Initiate TCP connection */

			if (connect(px_client->sockfd, rp->ai_addr, rp->ai_addrlen) != 0)  // If connected.
				goto next;

			goto success;
		}

		/* If initialization succeeded */

		success :

		if (rp->ai_family == AF_INET) {
			px_client->hostip = (char*) malloc(sizeof(char) * INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &((struct sockaddr_in*)rp->ai_addr)->sin_addr, \
					px_client->hostip, INET_ADDRSTRLEN);
		}
		else if (rp->ai_family == AF_INET6) {
			px_client->hostip = (char*) malloc(sizeof(char) * INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &((struct sockaddr_in*)rp->ai_addr)->sin_addr, \
					px_client->hostip, INET6_ADDRSTRLEN);
		}

		break;

		/* Try the next addrinfo structure*/

		next:
		close_proxy_client(px_client);
	}

	freeaddrinfo(result);

	if (rp == NULL)	{
		return_status = PROXY_ERROR_FATAL;
		goto init_error;
	}

	return PROXY_ERROR_NONE;

	init_error :
	close_proxy_client(px_client);
	px_client->hostip = NULL;

	return return_status;
}

int close_proxy_client(struct proxy_client* px_client)
{
	if (px_client == NULL)
		return PROXY_ERROR_INVAL;

	int return_status = PROXY_ERROR_NONE;

	/* Close socket connection */

	if (px_client->sockfd >= 0)	{

		if (close(px_client->sockfd) != 0)
			return_status = PROXY_ERROR_INVAL;

		px_client->sockfd = -1;
	}
	else
		return_status = PROXY_ERROR_INVAL;

	return return_status;
}

int free_proxy_client(struct proxy_client** px_client)
{
	if (px_client == NULL || *px_client == NULL)
		return PROXY_ERROR_INVAL;

	/* Close any existing open connections */

	int return_status = close_proxy_client(*px_client);

	/* Free pointers */

	free((*px_client)->hostname);
	free((*px_client)->port);
	free((*px_client)->hostip);

	/* Free structure */

	free(*px_client);
	*px_client = NULL;

	return return_status;
}

int proxy_socket_write(struct proxy_client* px_client, struct proxy_data* px_data, int sw_flags, \
		long* sw_status) {
	if (px_client == NULL || px_client->sockfd < 0 || px_data == NULL || \
			px_data->data == NULL || px_data->size <= 0) {
		sw_status != NULL ? *sw_status = 0 : 0;
		return PROXY_ERROR_INVAL;
	}

	/* Set the socket mode to non-blocking */

	int sock_args = fcntl(px_client->sockfd, F_GETFL);

	if (sock_args < 0) {
		sw_status != NULL ? *sw_status = 0 : 0;
		return PROXY_ERROR_INVAL;
	}

	int no_block = sock_args & O_NONBLOCK;

	if (!no_block) {
		if (fcntl(px_client->sockfd, F_SETFL, sock_args | O_NONBLOCK) < 0) {
			sw_status != NULL ? *sw_status = 0 : 0;
			return PROXY_ERROR_INVAL;
		}
	}

	/* Timeout initializations */

	struct timeval *wr_time, tp_time;

	if (px_client->io_timeout > 0) {
		wr_time = (struct timeval*) malloc(sizeof(struct timeval));
		wr_time->tv_sec = px_client->io_timeout;
		wr_time->tv_usec  = 0;
	}
	else
		wr_time = NULL;

	/* Select initializations */

	fd_set wr_set, tw_set;
	FD_ZERO(&wr_set);
	FD_SET(px_client->sockfd, &wr_set);

	int maxfds = px_client->sockfd + 1, sl_status = 0;

	/* Signal mask initializations */

	int sigfd = -1;
	struct signalfd_siginfo sigbuf;
	fd_set rd_set, tr_set;
	FD_ZERO(&rd_set);

	if (px_client->sigmask != NULL) {
		sigfd = signalfd(-1, px_client->sigmask, 0);

		if (sigfd < 0) {
			sw_status != NULL ? *sw_status = 0 : 0;
			return PROXY_ERROR_INVAL;
		}

		FD_SET(sigfd, &rd_set);
		maxfds = sigfd > px_client->sockfd ? sigfd + 1 : px_client->sockfd + 1;
	}

	/* Write to socket or Timeout or Respond to signal */

	long wr_status = 0, wr_counter = 0;
	int return_status = PROXY_ERROR_NONE;

	for ( ; ; ) {
		/* Wait for an event to occur */

		tw_set = wr_set;
		sl_status = select(maxfds, px_client->sigmask == NULL ? NULL : (tr_set = rd_set, &tr_set), &tw_set, NULL,\
				wr_time == NULL ? NULL : (tp_time = *wr_time, &tp_time));

		/* Check select return status */

		if (sl_status < 0) {
			if (errno == EINTR) {
				if (sw_flags & PROXY_MODE_AUTO_RETRY)
					continue;
				else {
					return_status = PROXY_ERROR_RETRY;
					goto write_return;
				}
			}
			else {
				return_status = PROXY_ERROR_FATAL;
				goto write_return;
			}
		}
		else if (sl_status == 0) {
			return_status = PROXY_ERROR_TIMEOUT;
			goto write_return;
		}

		/* Check if signal received */

		if (px_client->sigmask != NULL) {
			if (FD_ISSET(sigfd, &tr_set)) {
				read(sigfd, &sigbuf, sizeof(struct signalfd_siginfo));

				return_status = PROXY_ERROR_SIGRCVD;
				goto write_return;
			}
		}

		/* Check if socket is made writable */

		if (!FD_ISSET(px_client->sockfd, &tw_set)) {
			return_status = PROXY_ERROR_FATAL;
			goto write_return;
		}

		/* Commence the write operation */

		wr_status = write(px_client->sockfd, px_data->data + wr_counter, \
				px_data->size - wr_counter);

		/* Check write return status */

		if (wr_status < 0) {
			if (errno == EINTR) {
				if (sw_flags & PROXY_MODE_AUTO_RETRY)
					continue;
				else {
					return_status = PROXY_ERROR_RETRY;
					goto write_return;
				}
			}
			else if (errno == EWOULDBLOCK || errno == EAGAIN) {
				if ((sw_flags & PROXY_MODE_AUTO_RETRY) || !no_block)	// We made it non-blocking!
					continue;
				else {
					return_status = PROXY_ERROR_RETRY;
					goto write_return;
				}
			}
			else {
				return_status = PROXY_ERROR_FATAL;
				goto write_return;
			}
		}

		if (wr_status > 0)
			wr_counter = wr_counter + wr_status;

		/* If fewer bytes are transfered */

		if (wr_counter < px_data->size) {
			if (sw_flags == PROXY_MODE_AUTO_RETRY)
				continue;
			else {
				return_status = PROXY_ERROR_RETRY;
				goto write_return;
			}
		}

		/* All bytes are transfered */

		return_status = PROXY_ERROR_NONE;
		goto write_return;
	}

	/* Return procedures */

	write_return:

	/* Revert back the socket mode */

	if (!no_block) {
		if (fcntl(px_client->sockfd, F_SETFL, sock_args) < 0)
			return_status = PROXY_ERROR_FATAL;
	}

	/* Close any signalfd if opened */

	if (px_client->sigmask != NULL && sigfd >= 0)
		close(sigfd);

	/* Set the write_status of the socket */

	sw_status != NULL ? *sw_status = wr_counter : 0;

	return return_status;
}

int proxy_socket_read(struct proxy_client* px_client, struct proxy_data* px_data, int sr_flags, \
		long* sr_status) {
	if (px_client == NULL || px_client->sockfd < 0 || px_data == NULL || \
			px_data->data == NULL || px_data->size <= 0) {
		sr_status != NULL ? *sr_status = 0 : 0;
		return PROXY_ERROR_INVAL;
	}

	/* Set the socket mode to non-blocking */

	int sock_args = fcntl(px_client->sockfd, F_GETFL);

	if (sock_args < 0) {
		sr_status != NULL ? *sr_status = 0 : 0;
		return PROXY_ERROR_INVAL;
	}

	int no_block = sock_args & O_NONBLOCK;

	if (!no_block) {
		if (fcntl(px_client->sockfd, F_SETFL, sock_args | O_NONBLOCK) < 0) {
			sr_status != NULL ? *sr_status = 0 : 0;
			return PROXY_ERROR_INVAL;
		}
	}

	/* Timeout initializations */

	struct timeval *rd_time, tp_time;

	if (px_client->io_timeout > 0) {
		rd_time = (struct timeval*) malloc(sizeof(struct timeval));
		rd_time->tv_sec = px_client->io_timeout;
		rd_time->tv_usec  = 0;
	}
	else
		rd_time = NULL;

	/* Select initializations */

	fd_set rd_set, tr_set;
	FD_ZERO(&rd_set);
	FD_SET(px_client->sockfd, &rd_set);

	int maxfds = px_client->sockfd + 1, sl_status = 0;

	/* Signal mask initializations */

	int sigfd = -1;
	struct signalfd_siginfo sigbuf;

	if (px_client->sigmask != NULL) {
		sigfd = signalfd(-1, px_client->sigmask, 0);

		if (sigfd < 0) {
			sr_status != NULL ? *sr_status = 0 : 0;
			return PROXY_ERROR_INVAL;
		}

		FD_SET(sigfd, &rd_set);
		maxfds = sigfd > px_client->sockfd ? sigfd + 1 : px_client->sockfd + 1;
	}

	/* Read from socket or Timeout or Respond to signal */

	long rd_status = 0, rd_counter = 0;
	int return_status = PROXY_ERROR_NONE;

	for ( ; ; ) {
		/* Wait for an event occur */

		tr_set = rd_set;
		sl_status = select(maxfds, &tr_set, NULL, NULL,\
				rd_time == NULL ? NULL : (tp_time = *rd_time, &tp_time));

		/* Check for select return status */

		if (sl_status < 0) {
			if (errno == EINTR) {
				if (sr_flags & PROXY_MODE_AUTO_RETRY)
					continue;
				else {
					return_status = PROXY_ERROR_RETRY;
					goto read_return;
				}
			}
			else {
				return_status = PROXY_ERROR_FATAL;
				goto read_return;
			}
		}
		else if (sl_status == 0) {
			return_status = PROXY_ERROR_TIMEOUT;
			goto read_return;
		}

		/* Check if signal is received */

		if (px_client->sigmask != NULL) {
			if (FD_ISSET(sigfd, &tr_set)) {
				read(sigfd, &sigbuf, sizeof(struct signalfd_siginfo));

				return_status = PROXY_ERROR_SIGRCVD;
				goto read_return;
			}
		}

		/* Check if socket is made writable */

		if (!FD_ISSET(px_client->sockfd, &tr_set)) {
			return_status = PROXY_ERROR_FATAL;
			goto read_return;
		}

		 /* Commence the Read operation */

		rd_status = read(px_client->sockfd, px_data->data + rd_counter, \
				px_data->size - rd_counter);

		/* Check for read return status */

		if (rd_status < 0) {
			if (errno == EINTR) {
				if (sr_flags & PROXY_MODE_AUTO_RETRY)
					continue;
				else {
					return_status = PROXY_ERROR_RETRY;
					goto read_return;
				}
			}
			else if (errno == EWOULDBLOCK || errno == EAGAIN) {
				if ((sr_flags & PROXY_MODE_AUTO_RETRY) || !no_block)	// We made it non-blocking!
					continue;
				else {
					return_status = PROXY_ERROR_RETRY;
					goto read_return;
				}
			}
			else if (errno == EFAULT) {
				return_status = PROXY_ERROR_BUFFER_FULL;
				goto read_return;
			}
			else {
				return_status = PROXY_ERROR_FATAL;
				goto read_return;
			}
		}
		else if (rd_status > 0) {
			rd_counter = rd_counter + rd_status;

			if (rd_counter == px_data->size) {
				return_status = PROXY_ERROR_BUFFER_FULL;
				goto read_return;
			}

			if (sr_flags & PROXY_MODE_AUTO_RETRY)
				continue;
			else {
				return_status = PROXY_ERROR_RETRY;
				goto read_return;
			}
		}
		else {
			return_status = PROXY_ERROR_NONE;
			goto read_return;
		}
	}

	/* Return procedures */

	read_return:

	 /* Revert back the socket mode */

	if (!no_block) {
		if (fcntl(px_client->sockfd, F_SETFL, sock_args) < 0)
			return_status = PROXY_ERROR_FATAL;
	}

	/* Close any opened signalfd */

	if (px_client->sigmask != NULL && sigfd >= 0)
		close(sigfd);

	/* Set the socket read status */

	sr_status != NULL ? *sr_status = rd_counter : 0;

	return return_status;
}
