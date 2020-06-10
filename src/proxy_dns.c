/*
 * proxy_dns.c
 *
 *  Created on: 31-May-2020
 *      Author: Mohith Reddy
 */

#include "proxy_dns.h"
#include "dns.h"
#include "proxy.h"
#include "proxy_structures.h"
#include "proxy_socket.h"
#include "firewall.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/select.h>

static struct proxy_bag* dns_bag = NULL;
static pthread_mutex_t dns_lock = PTHREAD_MUTEX_INITIALIZER;
static int handler_count = 0;

void* dns_proxy_init(void* _px_handler)
{
	int sigfd = -1;	// Few variables used by init_quit

	/* Update the DNS_PROXY handler count and initialize the dns_bag if not initialized */

	pthread_mutex_lock(&dns_lock);
	handler_count = handler_count + 1;

	if (dns_bag == NULL)
		dns_bag = create_proxy_bag();

	if (dns_bag == NULL) {
		pthread_mutex_unlock(&dns_lock);
		goto init_quit;
	}
	pthread_mutex_unlock(&dns_lock);

	/* Get the proxy_handler{} */

	if (_px_handler == NULL)
		goto init_quit;

	struct proxy_handler* px_handler = (struct proxy_handler*) _px_handler;

	/* Set up a DNS server */

	px_handler->pxl_server = socktype_create_proxy_client(PROXY_DEFAULT_SERVER_LISTENER, NULL, \
			px_handler->px_opt, SOCK_DGRAM);

	if (px_handler->pxl_server == NULL)
		goto init_quit;

	if (init_proxy_client(px_handler->pxl_server) != PROXY_ERROR_NONE)
		goto init_quit;

	/* Config firewall */

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

	maxfds = sigfd > px_handler->pxl_server->sockfd ? sigfd + 1 : \
			px_handler->pxl_server->sockfd + 1;

	/* Loop and accept connections */

	int sl_status = 0, dh_return = PROXY_ERROR_NONE;

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
			/* If signal received for termination */

			read(sigfd, &sigbuf, sizeof(struct signalfd_siginfo));

			goto init_quit;
		}
		else if (FD_ISSET(px_handler->pxl_server->sockfd, &tr_set)) {
			/* Accept incoming connections */

			dh_return = dns_proxy_handler(px_handler->pxl_server->sockfd);

			if (dh_return != PROXY_ERROR_NONE && dh_return != PROXY_ERROR_RETRY)
				goto init_quit;
		}
		else
			goto init_quit;
	}

	init_quit:

	/* Decrement the handler_count and free dns_bag{} if reached 0 */

	pthread_mutex_lock(&dns_lock);
	handler_count = handler_count - 1;

	if (handler_count == 0 && dns_bag != NULL) {
		free_proxy_bag(&dns_bag);
	}
	pthread_mutex_unlock(&dns_lock);

	/* Close the signal_fd */

	if (sigfd >= 0) {
		close(sigfd);
		sigfd = -1;
	}

	/* Deconfig firewall */

	deconfig_fwall(px_handler);

	/* Close DNS server */

	free_proxy_client(&px_handler->pxl_server);

	/* Signal main() if not signaled by */

	if (px_handler->quit <= 0) {
		px_handler->quit = 1;
		pthread_kill(px_handler->ptid, px_handler->px_opt->signo);
	}

	return NULL;
}

int dns_proxy_handler(int sockfd)
{
	if (sockfd < 0)
		return PROXY_ERROR_INVAL;

	struct sockaddr_in cliaddr;
	int addr_len = sizeof(struct sockaddr_in);
	struct proxy_data query_data;
	query_data.data = malloc(DNS_TRANSACTION_SIZE);

	/* Read the UDP datagram */

	query_data.size = recvfrom(sockfd, query_data.data, DNS_TRANSACTION_SIZE, 0, \
			(struct sockaddr*) &cliaddr, &addr_len);

	if (query_data.size < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return PROXY_ERROR_RETRY;
		else
			return PROXY_ERROR_FATAL;
	}

	/* Parse the DNS query */

	struct dns_msg* dns_query = parse_dns_msg(&query_data, DNS_MODE_COMPLETE);

	if (dns_query == NULL)
		return PROXY_ERROR_RETRY;

	/* */

	struct dns_msg* dns_response = proxy_dns_response(dns_query);

	/* Create raw dns data for sending to client */

	struct proxy_data* response_data = create_dns_msg(dns_response, DNS_MODE_COMPLETE);

	if (response_data == NULL)
		return PROXY_ERROR_RETRY;

	if (sendto(sockfd, response_data->data, response_data->size, 0, \
			(struct sockaddr*) &cliaddr, addr_len) != response_data->size) {
		return PROXY_ERROR_RETRY;
	}

	return PROXY_ERROR_NONE;
}

int validate_dns_proxy_handler(struct proxy_handler* px_handler)
{
	if (px_handler == NULL)
		return PROXY_ERROR_INVAL;

	if (px_handler->px_opt != NULL) {
		px_handler->px_opt->px_server = NULL;
		px_handler->px_opt->px_port = NULL;
	}

	return PROXY_ERROR_NONE;
}

struct dns_msg* proxy_dns_response(struct dns_msg* dns_query)
{
	if (dns_query == NULL || dns_query->header == NULL)
		return NULL;

	struct dns_msg* dns_response = (struct dns_msg*) calloc(1, sizeof(struct dns_msg));

	/* Fill the DNS header */

	dns_response->header = (struct dns_header*) calloc(1, sizeof(struct dns_header));

		/* DNS transaction ID */

	dns_response->header->id = dns_query->header->id;

		/* QRflag */

	dns_response->header->qr[0] = 1;

		/* Opcode */

	for (int i = 0; i < 4; i++) {
		dns_response->header->opcode[i] = dns_query->header->opcode[i];
	}

		/* AAflag */

	dns_response->header->aa[0] = 0;

		/* TCflag */

	dns_response->header->tc[0] = 0;

		/* RDflag */

	dns_response->header->rd[0] = dns_query->header->rd[0];

		/* RAflag */

	dns_response->header->ra[0] = 1;

		/* Z */

	for (int i = 0; i < 3; i++) {
		dns_response->header->z[i] = 0;
	}

		/* RCODE */

	for (int i = 0; i < 4; i++) {
		dns_response->header->rcode[i] = 0;
	}

		/* QDCOUNT */

	dns_response->header->qdcount = 0;

		/* NSCOUNT */

	dns_response->header->nscount = 0;

		/* ARCOUNT */

	dns_response->header->arcount = 0;

	/* Answers */

	dns_response->answer = (struct dns_rrecord*) calloc(dns_query->qdcount, sizeof(struct dns_rrecord));

	struct proxy_data* domain_data = NULL;
	unsigned int ans_count = 0;

	for (unsigned int ques_count; ques_count < dns_query->qdcount; ques_count++) {
		if (dns_query->question[ques_count].qtype != 1 || \
				dns_query->question[ques_count].qclass != 1) {
			continue;
		}

		/* Name */

		char* hostname = strdup(dns_query->question[ques_count].hname);
		hostname[strlen(hostname) - 1] = '\0';

		domain_data = host_to_domain(hostname);

		if (domain_data == NULL)
			continue;

		dns_response->answer[ans_count].name = domain_data->data;
		dns_response->answer[ans_count].name_len = domain_data->size;

		/* Type */

		dns_response->answer[ans_count].type = 1;

		/* Class */

		dns_response->answer[ans_count].class = 1;

		/* TTL */

		dns_response->answer[ans_count].ttl = PROXY_DNS_RESPONSE_DEFAULT_TTL;

		/* RDLENGTH */

		dns_response->answer[ans_count].rdlength = 4;

		/* RDATA */

		char* hostaddress = proxy_dns_resolve(hostname);

		if (hostaddress == NULL)
			continue;

		dns_response->answer[ans_count].rdata = calloc(1, 4);
		inet_pton(AF_INET, hostaddress, dns_response->answer[ans_count].rdata);

		//

		ans_count++;
	}

	dns_response->ancount = ans_count;

	/* DNS Header ANCOUNT */

	dns_response->header->ancount = ans_count;

	return dns_response;
}

char* proxy_dns_resolve(char* hostname)
{
	if (hostname == NULL)
		return NULL;

	struct dns_msg* dns_query = (struct dns_msg*) calloc(1, sizeof(struct dns_msg));

	/* Initialize the DNS header */

	dns_query->header = (struct dns_header*) calloc(1, sizeof(struct dns_header));

		/* QR flag */

	dns_query->header->qr[0] = 1;

		/* */
	return strdup("1.1.1.1");
}





