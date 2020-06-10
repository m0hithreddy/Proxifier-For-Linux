/*
 * proxy.c
 *
 *  Created on: 16-May-2020
 *      Author: Mohith Reddy
 */

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
		return NULL;

	/* Proxy Server information */

	if (px_opt->px_server != NULL) {
		dup_opt->px_server = strdup(px_opt->px_server);

		if (dup_opt->px_server == NULL)
			return NULL;
	}

	if (px_opt->px_port != NULL) {
		dup_opt->px_port = strdup(px_opt->px_port);

		if (dup_opt->px_port == NULL)
			return NULL;
	}

	if (px_opt->px_username != NULL) {
		dup_opt->px_username = strdup(px_opt->px_username);

		if (dup_opt->px_username == NULL)
			return NULL;
	}

	if (px_opt->px_password != NULL) {
		dup_opt->px_password = strdup(px_opt->px_password);

		if (dup_opt->px_password == NULL)
			return NULL;
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
			return NULL;
	}

	dup_opt->signo = px_opt->signo;

	return dup_opt;
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
			return NULL;
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
			return NULL;
	}
	else
		return NULL;

	return px_request;
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
