/*
 * proxy_http.c
 *
 *  Created on: 16-May-2020
 *      Author: Mohith Reddy
 */

#include "proxy_http.h"
#include "proxy.h"
#include "proxy_structures.h"
#include "proxy_socket.h"
#include "proxy_functions.h"
#include "http.h"
#include "base64.h"
#include "firewall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/select.h>
#include <linux/netfilter_ipv4.h>

void* http_proxy_init(void* _px_handler)
{
	/* Few variables initializations (used by init_quit) */

	int sigfd = -1;
	struct proxy_bag* request_bag = create_proxy_bag();

	if (_px_handler == NULL)	// Invalid parameters
		goto init_quit;

	struct proxy_handler* px_handler = (struct proxy_handler*) _px_handler;

	/* Setup a listening socket */

	px_handler->pxl_server = ai_flags_create_proxy_client(PROXY_DEFAULT_SERVER_LISTENER, NULL, \
			px_handler->px_opt, AI_PASSIVE);

	if (init_proxy_client(px_handler->pxl_server) != PROXY_ERROR_NONE)
		goto init_quit;

	/* Setup system and protocol specific things */

	if (px_handler->px_opt->px_username != NULL && px_handler->px_opt->px_password != NULL) {
		/* Base64 encode username:password */

		char* user_pass = strappend(3, px_handler->px_opt->px_username, ":", px_handler->px_opt->px_password);
		char* user_pass64 = base64_encode(user_pass, strlen(user_pass), NULL);

		px_handler->proto_data = (void*) strappend(3, PROXY_DEFAULT_HTTP_PROXY_AUTHORIZATION_SCHEME, \
				" ", user_pass64);	// Proxy-Authorization header
	}

	/* Configure Firewall */

	if (config_fwall(px_handler) != PROXY_ERROR_NONE)
		goto init_quit;

	/* Set the socket in non-blocking mode */

	int sock_args = fcntl(px_handler->pxl_server->sockfd, F_GETFL);

	if (sock_args < 0)
		goto init_quit;

	if (fcntl(px_handler->pxl_server->sockfd, F_SETFL, sock_args | O_NONBLOCK) < 0)
		goto init_quit;

	/* Select variables initializations */

	fd_set rd_set, tr_set;
	FD_ZERO(&rd_set);
	FD_SET(px_handler->pxl_server->sockfd, &rd_set);

	int maxfds = -1;

	/* Setup signal handler */

	struct signalfd_siginfo sigbuf;

	if ((sigfd = signalfd(-1, px_handler->px_opt->sigmask, 0)) < 0)
		goto init_quit;

	FD_SET(sigfd, &rd_set);

	maxfds = sigfd > px_handler->pxl_server->sockfd ? sigfd + 1 : px_handler->pxl_server->sockfd + 1;

	/* Loop and accept connections */

	int sl_status = 0;

	for ( ; ; ) {

		tr_set = rd_set;
		sl_status = select(maxfds, &tr_set, NULL, NULL, NULL);

		if (sl_status < 0) {
			if (errno == EINTR)
				continue;
			else
				goto init_quit;
		}
		else if (sl_status == 0)
			continue;

		if (FD_ISSET(sigfd, &tr_set)) {
			read(sigfd, &sigbuf, sizeof(struct signalfd_siginfo));

			if (px_handler->quit)
				goto init_quit;

			for (struct proxy_pocket* px_pocket = request_bag->start; px_pocket != NULL; \
			px_pocket = px_pocket->next) {
				if ((*((struct proxy_request**) px_pocket->data))->quit) {
					pthread_join((*((struct proxy_request**) px_pocket->data))->tid, NULL);
					free_proxy_request((struct proxy_request**) px_pocket->data, http_data_free);
					delete_proxy_pocket(request_bag, &px_pocket);
					break;
				}
			}
		}
		else if (FD_ISSET(px_handler->pxl_server->sockfd, &tr_set)) {
			/* Accept incoming connections */

			struct proxy_request* px_request = create_proxy_request(px_handler, http_data_setup);

			if (px_request == NULL)
				goto init_quit;

			px_request->sockfd = accept(px_handler->pxl_server->sockfd, (struct sockaddr*) &(px_request->addr), \
					&(px_request->addr_len));

			if (px_request->sockfd < 0) {
				free_proxy_request(&px_request, http_data_free);

				if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
					continue;
				else
					goto init_quit;
			}

			/* Create a proxy_client{} for already accepted client connection for socket operations */

			px_request->px_client = ai_flags_sockfd_create_proxy_client(NULL, NULL, px_request->px_opt, \
					-1, px_request->sockfd);

			if (px_request->px_client == NULL) {
				goto init_quit;
			}

			/* Create thread for handling client */

			if (pthread_create(&(px_request->tid), NULL, http_proxy_handler, (void*) px_request) != 0) {
				close(px_request->sockfd);
				free_proxy_request(&px_request, http_data_free);

				continue;
			}

			place_proxy_data(request_bag, &((struct proxy_data) {(void*) &px_request, \
				sizeof(struct proxy_request*)}));
		}
		else
			goto init_quit;
	}

	init_quit:
	/* Deconfig firewall rules */

	deconfig_fwall(px_handler);

	/* Stop accepting connections */

	free_proxy_client(&px_handler->pxl_server);

	/* Close signalfd socket */

	if (sigfd >= 0)	{
		close(sigfd);
		sigfd = -1;
	}

	/* Terminate all handlers */

	for (struct proxy_pocket* px_pocket = request_bag->start; px_pocket != NULL; \
	px_pocket = px_pocket->next) {
		/* Signal the http_handlers for termination */

		(*((struct proxy_request**) px_pocket->data))->quit = 1;
		pthread_kill((*((struct proxy_request**) px_pocket->data))->tid, \
				(*((struct proxy_request**) px_pocket->data))->px_opt->signo);
	}

	for (struct proxy_pocket* px_pocket = request_bag->start; px_pocket != NULL; \
	px_pocket = px_pocket->next) {
		/* Wait for threads to join */
		pthread_join((*((struct proxy_request**) px_pocket->data))->tid, NULL);

		/* Free structures */
		free_proxy_request((struct proxy_request**) px_pocket->data, http_data_free);
	}

	free_proxy_bag(&request_bag);

	/* Signal parent if it did'nt request for termination */

	if (!px_handler->quit) {
		px_handler->quit = 1;
		pthread_kill(px_handler->ptid, px_handler->px_opt->signo);
	}

	return NULL;
}

void* http_proxy_handler(void* _px_request)
{
	struct proxy_request* px_request = (struct proxy_request*) _px_request;
	struct proxy_client *px_server = NULL;
	int sigfd = -1;

	if (px_request == NULL)
		goto handler_quit;

	/* Set up a connection with proxy_server */

	px_server = create_proxy_client(px_request->px_opt->px_server, px_request->px_opt->px_port, \
			px_request->px_opt);

	if (init_proxy_client(px_server) != PROXY_ERROR_NONE)
		goto handler_quit;

	/* Get the original destination sockaddr_storage{} */

	struct sockaddr_storage org_addr;
	int org_addrlen = sizeof(struct sockaddr_storage);

	if (getsockopt(px_request->px_client->sockfd, SOL_IP, SO_ORIGINAL_DST, (void*) &org_addr, \
			&org_addrlen) != 0) {
		goto handler_quit;
	}

	/* Get the original destination IP */

	char* org_dst = (char*) malloc(sizeof(char) * (org_addr.ss_family == AF_INET ? \
			INET_ADDRSTRLEN : INET6_ADDRSTRLEN));

	if (org_addr.ss_family == AF_INET) {
		org_dst = (char*) malloc(sizeof(char) * INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void*) (&((struct sockaddr_in*) &org_addr)->sin_addr), org_dst, \
				INET_ADDRSTRLEN);
	}
	else if (org_addr.ss_family == AF_INET6) {
		org_dst = (char*) malloc(sizeof(char) * INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void*) (&((struct sockaddr_in6*) &org_addr)->sin6_addr), org_dst, \
				INET6_ADDRSTRLEN);
	}

	/* Get the original destination port */

	char* org_port = (char*) malloc(6 * sizeof(char));

	snprintf(org_port, 6, "%d", htons(org_addr.ss_family == AF_INET ? \
			((struct sockaddr_in*) &org_addr)->sin_port : ((struct sockaddr_in6*) &org_addr)->sin6_port));

	/* Create HTTP request */

	struct http_request s_request;
	memset(&s_request, 0, sizeof(struct http_request));

	s_request.method = "CONNECT";
	s_request.path = strappend(3, org_dst, ":", org_port);
	s_request.version = "1.1";
	s_request.host = strdup(org_dst);
	s_request.user_agent = PROXY_DEFAULT_HTTP_USER_AGENT;

	if (px_request->proto_data != NULL) {
		s_request.proxy_authorization = strdup((char*) px_request->proto_data);
	}

	s_request.proxy_connection = "Keep-Alive";

	struct proxy_data* request = create_http_request(&s_request);

	/* Send HTTP request and Read headers */

	struct proxy_bag* http_results = create_proxy_bag();

	if (http_method(px_server, request, HTTP_MODE_SEND_REQUEST | HTTP_MODE_READ_HEADERS, http_results) \
			!= PROXY_ERROR_NONE) {
		goto handler_quit;
	}

	struct http_response* s_response = parse_http_response((struct proxy_data*) http_results->start->data);

	/* Check if CONNECT succeeded */

	if (s_response == NULL || s_response->status_code == NULL || \
			strcmp(s_response->status_code, "200") != 0) {
		goto handler_quit;
	}

	/* Timeout initializations */

	struct timeval *rd_timeo = NULL, tp_timeo;

	if (px_request->px_opt->io_timeout > 0) {
		rd_timeo = (struct timeval*) malloc(sizeof(struct timeval));
		rd_timeo->tv_sec = px_request->px_opt->io_timeout;
		rd_timeo->tv_usec = 0;
	}
	else
		rd_timeo = NULL;

	/* Select variables initializations */

	fd_set rd_set, tr_set;
	FD_ZERO(&rd_set);
	FD_SET(px_request->px_client->sockfd, &rd_set);
	FD_SET(px_server->sockfd, &rd_set);

	int maxfds = px_request->px_client->sockfd > px_server->sockfd ? px_request->px_client->sockfd + 1 : px_server->sockfd + 1;

	/* Signalfd initializations */

	sigfd = signalfd(-1, px_request->px_opt->sigmask, 0);

	if (sigfd < 0)
		goto handler_quit;

	struct signalfd_siginfo sigbuf;

	FD_SET(sigfd, &rd_set);
	maxfds = sigfd + 1 > maxfds ? sigfd + 1 : maxfds;

	/* Tunnel data between client and proxy server */

	struct proxy_data* tun_data = create_proxy_data(PROXY_MAX_TRANSACTION_SIZE);
	long rd_status = 0, rd_return = PROXY_ERROR_NONE;

	for ( ; ; ) {
		tr_set = rd_set;

		if (select(maxfds, &tr_set, NULL, NULL, rd_timeo != NULL ? \
				tp_timeo = *rd_timeo, &tp_timeo : NULL) < 0) {
			goto handler_quit;
		}

		if (FD_ISSET(sigfd, &tr_set)) {
			read(sigfd, &sigbuf, sizeof(struct signalfd_siginfo));
			goto handler_quit;
		}
		else if (FD_ISSET(px_request->px_client->sockfd, &tr_set)) {
			rd_status = 0;
			tun_data->size = PROXY_MAX_TRANSACTION_SIZE;
			rd_return = proxy_socket_read(px_request->px_client, tun_data, PROXY_MODE_PARTIAL, &rd_status);

			if (rd_return != PROXY_ERROR_NONE && rd_return != PROXY_ERROR_RETRY \
					&& rd_return != PROXY_ERROR_BUFFER_FULL){
				goto handler_quit;
			}

			if (rd_status > 0) {
				tun_data->size = rd_status;

				if (proxy_socket_write(px_server, tun_data, PROXY_MODE_AUTO_RETRY, \
						NULL) != PROXY_ERROR_NONE) {
					goto handler_quit;
				}
			}

			if (rd_return == PROXY_ERROR_NONE)
				goto handler_quit;
		}
		else if (FD_ISSET(px_server->sockfd, &tr_set)) {
			rd_status = 0;
			tun_data->size = PROXY_MAX_TRANSACTION_SIZE;
			rd_return = proxy_socket_read(px_server, tun_data, PROXY_MODE_PARTIAL, &rd_status);

			if (rd_return != PROXY_ERROR_NONE && rd_return != PROXY_ERROR_RETRY \
					&& rd_return != PROXY_ERROR_BUFFER_FULL){
				goto handler_quit;
			}

			if (rd_status > 0) {
				tun_data->size = rd_status;

				if (proxy_socket_write(px_request->px_client, tun_data, PROXY_MODE_AUTO_RETRY, \
						NULL) != PROXY_ERROR_NONE) {
					goto handler_quit;
				}
			}

			if (rd_return == PROXY_ERROR_NONE)
				goto handler_quit;
		}
		else
			goto handler_quit;
	}

	handler_quit:
	free_proxy_client(&px_server);

	if (sigfd >= 0) {
		close(sigfd);
		sigfd = -1;
	}

	if (!px_request->quit) {
		px_request->quit = 1;
		pthread_kill(px_request->ptid, px_request->px_opt->signo);
	}

	return NULL;
}

int http_data_setup(struct proxy_handler* px_handler, void** _http_data)
{
	if (px_handler == NULL || _http_data == NULL)
		return PROXY_ERROR_INVAL;

	if (px_handler->proto_data != NULL) {
		*_http_data = strdup((char*) px_handler->proto_data);

		if (*_http_data == NULL)
			return PROXY_ERROR_INVAL;
	}

	return PROXY_ERROR_NONE;
}

int http_data_free(void** _http_data)
{
	if (_http_data == NULL || *_http_data == NULL)
		return PROXY_ERROR_INVAL;

	free(*_http_data);
	*_http_data = NULL;

	return PROXY_ERROR_NONE;
}

