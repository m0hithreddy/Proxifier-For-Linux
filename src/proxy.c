/*
 * proxy.c
 *
 *  Created on: 16-May-2020
 *      Author: Mohith Reddy
 */

#include "proxy.h"
#include "proxy_functions.h"
#include "proxy_socket.h"
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

struct proxy_options* create_proxy_options(struct proxy_options* px_opt)
{
	if (px_opt == NULL)
		return NULL;

	struct proxy_options* dup_opt = (struct proxy_options*) calloc(1, sizeof(struct proxy_options));

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

int free_proxy_options(struct proxy_options** px_opt)
{
	if (px_opt == NULL || *px_opt == NULL)
		return PROXY_ERROR_INVAL;

	/* Free pointers */

	free((*px_opt)->px_server);
	free((*px_opt)->px_port);
	free((*px_opt)->px_username);
	free((*px_opt)->px_password);
	free((*px_opt)->sigmask);

	/* Free px_opt{} */

	free(*px_opt);
	*px_opt = NULL;

	return PROXY_ERROR_NONE;
}

struct proxy_handler* create_proxy_handler()
{
	struct proxy_handler* px_handler = (struct proxy_handler*) calloc(1, sizeof(struct proxy_handler));

	px_handler->px_opt = (struct proxy_options*) calloc(1, sizeof(struct proxy_options));

	px_handler->px_opt->px_server = "192.168.43.231";
	px_handler->px_opt->px_port = "3128";
	px_handler->px_opt->px_username = NULL;
	px_handler->px_opt->px_password = NULL;
	px_handler->px_opt->nrd_ports = 2;
	px_handler->px_opt->rd_ports = malloc(sizeof(char*) * px_handler->px_opt->nrd_ports);
	px_handler->px_opt->rd_ports[0] = "80";
	px_handler->px_opt->rd_ports[1] = "443";
	/* Network-Variables */
	px_handler->px_opt->io_timeout = 60;
	/* Signal Variables */
	px_handler->px_opt->signo = SIGRTMIN;
	px_handler->px_opt->sigmask = malloc(sizeof(sigset_t));
	sigemptyset(px_handler->px_opt->sigmask);
	sigaddset(px_handler->px_opt->sigmask, px_handler->px_opt->signo);

	px_handler->quit = 0;
	px_handler->proto_data = NULL;

	return px_handler;
}

struct proxy_request* create_proxy_request(struct proxy_handler* px_handler, protocol_data_setup proto_data_setup)
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

	px_request->ptid = pthread_self();
	px_request->px_client = NULL;

	/* Variables for Synchronization */

	px_request->quit = 0;

	/* Variables for socket operations */

	px_request->sockfd = -1;
	memset(&px_request->addr, 0, sizeof(struct sockaddr_storage));
	px_request->addr_len = sizeof(struct sockaddr_storage);

	/* Protocol specific data */

	if (proto_data_setup != NULL) {
		if ((*proto_data_setup)(px_handler, &(px_request->proto_data)) != PROXY_ERROR_NONE)
			return NULL;
	}

	return px_request;
}

int free_proxy_request(struct proxy_request** px_request, protocol_data_free proto_data_free)
{
	if (px_request == NULL || *px_request == NULL)
		return PROXY_ERROR_INVAL;

	int free_status = PROXY_ERROR_NONE;

	/* Free pointers */

	if ((*px_request)->px_opt != NULL) {
		if (free_proxy_options(&((*px_request)->px_opt)) != PROXY_ERROR_NONE)
			free_status = PROXY_ERROR_INVAL;
	}

	if ((*px_request)->px_client != NULL) {
		if (free_proxy_client(&((*px_request)->px_client)) != PROXY_ERROR_NONE)
			free_status = PROXY_ERROR_INVAL;
	}

	if (proto_data_free != NULL && (*px_request)->proto_data != NULL) {
		if ((*proto_data_free)(&((*px_request)->proto_data)) != PROXY_ERROR_NONE)
			free_status = PROXY_ERROR_INVAL;
	}

	/* Free px_request{} */

	free(*px_request);
	*px_request = NULL;

	return free_status;
}
