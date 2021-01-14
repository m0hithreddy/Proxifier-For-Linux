/*******************************************************************************
 * Copyright (C) 2020 - 2021, Mohith Reddy <dev.m0hithreddy@gmail.com>
 *
 * This file is part of Proxifier-For-Linux <https://github.com/m0hithreddy/Proxifier-For-Linux>
 *
 * Proxifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Proxifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *******************************************************************************/

#include "proxy.h"
#include "proxy_functions.h"
#include "proxy_socket.h"
#include "proxy_http.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>

struct in_addr* get_lo_interface_in_addr()
{
	struct in_addr* lo_in_addr = (struct in_addr*) calloc(1, sizeof(struct in_addr));

	lo_in_addr->s_addr = htonl(INADDR_LOOPBACK);

	return lo_in_addr;
}

sigset_t* get_syncmask(void)
{
	sigset_t* sigmask = (sigset_t*) malloc(sizeof(sigset_t));
	sigemptyset(sigmask);
	sigaddset(sigmask, PROXY_DEFAULT_SYNC_SIGNAL);

	return sigmask;
}

struct proxy_options* create_proxy_options(struct proxy_options* px_opt)
{
	if (px_opt == NULL)
		return NULL;

	struct proxy_options* dup_opt = (struct proxy_options*) calloc(1, \
			sizeof(struct proxy_options));

	if (dup_opt == NULL)
		goto cpo_error;

	/* Proxy Server information */

	if (px_opt->px_server != NULL) {
		dup_opt->px_server = strdup(px_opt->px_server);

		if (dup_opt->px_server == NULL)
			goto cpo_error;
	}

	if (px_opt->px_port != NULL) {
		dup_opt->px_port = strdup(px_opt->px_port);

		if (dup_opt->px_port == NULL)
			goto cpo_error;
	}

	if (px_opt->px_username != NULL) {
		dup_opt->px_username = strdup(px_opt->px_username);

		if (dup_opt->px_username == NULL)
			goto cpo_error;
	}

	if (px_opt->px_password != NULL) {
		dup_opt->px_password = strdup(px_opt->px_password);

		if (dup_opt->px_password == NULL)
			goto cpo_error;
	}

	/* Redirection variables */

	if (px_opt->nrd_ports > 0) {
		dup_opt->nrd_ports = px_opt->nrd_ports;
		dup_opt->rd_ports = (char**) malloc(sizeof(char*) * px_opt->nrd_ports);

		for (long port_count = 0; port_count < px_opt->nrd_ports; port_count++) {
			if (px_opt->rd_ports[port_count] != NULL)
				dup_opt->rd_ports[port_count] = strdup(px_opt->rd_ports[port_count]);
		}
	}

	/* Network Variables */

	dup_opt->io_timeout = px_opt->io_timeout;

	/* Signal variables */

	if (px_opt->sigmask != NULL) {
		dup_opt->sigmask = memndup(px_opt->sigmask, sizeof(sigset_t));

		if (dup_opt->sigmask == NULL)
			goto cpo_error;
	}

	dup_opt->signo = px_opt->signo;

	return dup_opt;

	cpo_error:
	
	free_proxy_options(&dup_opt);
	return NULL;
}

int free_proxy_options(struct proxy_options** _px_opt)
{
	if (_px_opt == NULL || *_px_opt == NULL)
		return PROXY_ERROR_INVAL;

	struct proxy_options* px_opt = *_px_opt;

	/* Free double pointers */

	if (px_opt->nrd_ports > 0) {
		for (long port_count = 0; port_count < px_opt->nrd_ports; \
		port_count++) {
			free(px_opt->rd_ports[port_count]);
		}

		free(px_opt->rd_ports);
	}

	/* Free Pointers */

	free(px_opt->px_server);
	free(px_opt->px_port);
	free(px_opt->px_username);
	free(px_opt->px_password);
	free(px_opt->sigmask);

	/* Free px_opt{} */

	free(px_opt);
	*_px_opt = NULL;

	return PROXY_ERROR_NONE;
}

int free_proxy_handler(struct proxy_handler** _px_handler)
{
	if (_px_handler == NULL || *_px_handler == NULL)
		return PROXY_ERROR_INVAL;

	struct proxy_handler* px_handler = *_px_handler;

	int return_status = PROXY_ERROR_NONE;

	/* Free Proxy Options */

	if (px_handler->px_opt != NULL) {
		if (free_proxy_options(&px_handler->px_opt) != PROXY_ERROR_NONE)
			return_status = PROXY_ERROR_INVAL;
	}

	/* Thread variables */

	if (px_handler->pxl_server != NULL) {
		if (free_proxy_client(&px_handler->pxl_server) != PROXY_ERROR_NONE)
			return_status = PROXY_ERROR_INVAL;
	}

	/* Protocol specific data */

	if (px_handler->proto_data != NULL) {
		if (px_handler->protocol == PROXY_PROTOCOL_HTTP) {
			if (free_http_proxy_handler(px_handler) != PROXY_ERROR_NONE)
				return_status = PROXY_ERROR_INVAL;
		}
		else
			free(px_handler->proto_data);
	}

	/* Free px_handler{} */

	free(px_handler);
	*_px_handler = NULL;

	return return_status;
}

struct proxy_request* create_proxy_request(struct proxy_handler* px_handler)
{
	if (px_handler == NULL)
		return NULL;

	struct proxy_request* px_request = (struct proxy_request*) calloc(1, sizeof(struct proxy_request));

	/* Duplicate proxy_options{} */

	if (px_handler->px_opt != NULL) {
		px_request->px_opt = create_proxy_options(px_handler->px_opt);

		if (px_request->px_opt == NULL)
			goto cpr_error;
	}

	/* Thread Variables */

	px_request->ptid = px_handler->tid;

	/* Variables for Synchronization */


	/* Variables for socket operations */

	px_request->sockfd = -1;
	px_request->addr_len = sizeof(struct sockaddr_storage);

	/* Protocol specific data */

	px_request->protocol = px_handler->protocol;

	if (px_request->protocol == PROXY_PROTOCOL_HTTP) {
		if (fill_http_proxy_request(px_handler, px_request) != PROXY_ERROR_NONE)
			goto cpr_error;
	}
	else
		goto cpr_error;

	return px_request;

	cpr_error:

	free_proxy_request(&px_request);
	return NULL;
}

int free_proxy_request(struct proxy_request** _px_request)
{
	if (_px_request == NULL || *_px_request == NULL)
		return PROXY_ERROR_INVAL;

	int free_status = PROXY_ERROR_NONE;

	struct proxy_request* px_request = *_px_request;

	/* Free pointers */

	if (px_request->px_opt != NULL) {
		if (free_proxy_options(&px_request->px_opt) != PROXY_ERROR_NONE)
			free_status = PROXY_ERROR_INVAL;
	}

	if (px_request->px_client != NULL) {
		if (free_proxy_client(&px_request->px_client) != PROXY_ERROR_NONE)
			free_status = PROXY_ERROR_INVAL;
	}

	if (px_request->proto_data != NULL) {
		if (px_request->protocol == PROXY_PROTOCOL_HTTP) {
			if (free_http_proxy_request(px_request) != PROXY_ERROR_NONE)
				free_status = PROXY_ERROR_INVAL;
		}
		else
			free(px_request->proto_data);
	}

	/* Free px_request{} */

	free(*_px_request);
	*_px_request = NULL;

	return free_status;
}
