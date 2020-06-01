/*
 * proxy_socket.h
 *
 *  Created on: 16-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_PROXY_SOCKET_H_
#define SRC_PROXY_SOCKET_H_

#define PROXY_MODE_AUTO_RETRY 0b1
#define PROXY_MODE_PARTIAL 0b0

#include "proxy.h"
#include "proxy_structures.h"
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>

struct proxy_client	{
	/* Proxy server information */
	char* hostname;
	char* port;
	/* Socket variables */
	int family;
	int type;
	int protocol;
	/* getaddrinfo() variables */
	int ai_flags;
	/* Network variables */
	long io_timeout;
	/* Synchronization variables */
	sigset_t* sigmask;
	/* Results */
	int sockfd;
	char* hostip;
};

struct proxy_client* ai_flags_sockfd_socktype_create_proxy_client(const char* hostname, const char* port, \
		struct proxy_options* px_opt, int ai_flags, int sockfd, int socktype);

int init_proxy_client(struct proxy_client* px_client);

int close_proxy_client(struct proxy_client* px_client);

int free_proxy_client(struct proxy_client** px_client);

int proxy_socket_write(struct proxy_client* px_client, struct proxy_data* px_data, int sw_flags, \
		long* sw_status);

int proxy_socket_read(struct proxy_client* px_client, struct proxy_data* px_data, int sr_flags, \
		long* sr_status);

#define create_proxy_client(hostname, port, px_opt) ai_flags_sockfd_socktype_create_proxy_client(hostname, \
		port, px_opt, AI_ADDRCONFIG, -1, SOCK_STREAM)

#define ai_flags_create_proxy_client(hostname, port, px_opt, ai_flags) ai_flags_sockfd_socktype_create_proxy_client(hostname, \
		port, px_opt, ai_flags, -1, SOCK_STREAM)

#define ai_flags_sockfd_create_proxy_client(hostname, port, px_opt, ai_flags, sockfd) ai_flags_sockfd_socktype_create_proxy_client(hostname, port, \
		px_opt, ai_flags, sockfd, SOCK_STREAM)

#define socktype_create_proxy_client(hostname, port, px_opt, socktype) ai_flags_sockfd_socktype_create_proxy_client(hostname, port, \
		px_opt, AI_ADDRCONFIG, -1, socktype)

#endif /* SRC_PROXY_SOCKET_H_ */
