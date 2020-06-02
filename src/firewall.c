/*
 * firewall.c
 *
 *  Created on: 22-May-2020
 *      Author: Mohith Reddy
 */

#include "firewall.h"
#include "proxy.h"
#include "proxy_functions.h"
#include "proxy_socket.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

static pthread_mutex_t fwall_lock = PTHREAD_MUTEX_INITIALIZER;

int config_fwall(struct proxy_handler* px_handler)
{
	if (px_handler == NULL || px_handler->px_opt == NULL || px_handler->pxl_server == NULL) {
		return PROXY_ERROR_INVAL;
	}

	if (px_handler->px_opt->px_server != NULL) {
		/* Bypass Proxy Server Traffic */

		if (px_handler->pxl_server->type == SOCK_STREAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_INSERT_AT_TOP, FIREWALL_CONSTANT_TCP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION, \
					px_handler->px_opt->px_server, FIREWALL_CONSTANT_TARGET_ACCEPT, NULL);

		}
		else if (px_handler->pxl_server->type == SOCK_DGRAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_INSERT_AT_TOP, FIREWALL_CONSTANT_UDP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION, \
					px_handler->px_opt->px_server, FIREWALL_CONSTANT_TARGET_ACCEPT, NULL);

		}
		else {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_INSERT_AT_TOP, FIREWALL_CONSTANT_ALL_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION, \
					px_handler->px_opt->px_server, FIREWALL_CONSTANT_TARGET_ACCEPT, NULL);

		}
	}

	if (px_handler->px_opt->rd_ports != NULL && px_handler->px_opt->nrd_ports > 0 && \
			px_handler->pxl_server->hostip != NULL && px_handler->pxl_server->port != NULL) {
		/* Redirects traffic coming from specific ports to server */

		char* ports_string = "";

		for (long port_count = 0; port_count < px_handler->px_opt->nrd_ports; \
		port_count++) {
			if (port_count == px_handler->px_opt->nrd_ports - 1) {
				ports_string = strappend(2, ports_string, \
						px_handler->px_opt->rd_ports[port_count]);
			}
			else {
				ports_string = strappend(3, ports_string, \
						px_handler->px_opt->rd_ports[port_count], ",");
			}
		}

		if (px_handler->pxl_server->type == SOCK_STREAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_INSERT_AT_BOTTOM, FIREWALL_CONSTANT_TCP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION, \
					ports_string, FIREWALL_CONSTANT_TARGET_DNAT, FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION, \
					strappend(3, px_handler->pxl_server->hostip, ":", px_handler->pxl_server->port), NULL);
		}
		else if (px_handler->pxl_server->type == SOCK_DGRAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_INSERT_AT_BOTTOM, FIREWALL_CONSTANT_UDP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION, \
					ports_string, FIREWALL_CONSTANT_TARGET_DNAT, FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION, \
					strappend(3, px_handler->pxl_server->hostip, ":", px_handler->pxl_server->port), NULL);

		}
		else {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_INSERT_AT_BOTTOM, FIREWALL_CONSTANT_ALL_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION, \
					ports_string, FIREWALL_CONSTANT_TARGET_DNAT, FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION, \
					strappend(3, px_handler->pxl_server->hostip, ":", px_handler->pxl_server->port), NULL);
		}
	}

	return PROXY_ERROR_NONE;
}

int deconfig_fwall(struct proxy_handler* px_handler)
{

	if (px_handler == NULL || px_handler->px_opt == NULL || px_handler->pxl_server == NULL) {
		return PROXY_ERROR_INVAL;
	}

	if (px_handler->px_opt->px_server != NULL) {
		/* Bypass Proxy Server Traffic */

		if (px_handler->pxl_server->type == SOCK_STREAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_DELETE, FIREWALL_CONSTANT_TCP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION, \
					px_handler->px_opt->px_server, FIREWALL_CONSTANT_TARGET_ACCEPT, NULL);

		}
		else if (px_handler->pxl_server->type == SOCK_DGRAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_DELETE, FIREWALL_CONSTANT_UDP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION, \
					px_handler->px_opt->px_server, FIREWALL_CONSTANT_TARGET_ACCEPT, NULL);

		}
		else {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_DELETE, FIREWALL_CONSTANT_ALL_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION, \
					px_handler->px_opt->px_server, FIREWALL_CONSTANT_TARGET_ACCEPT, NULL);

		}
	}

	if (px_handler->px_opt->rd_ports != NULL && px_handler->px_opt->nrd_ports > 0 && \
			px_handler->pxl_server->hostip != NULL && px_handler->pxl_server->port != NULL) {
		/* Remove Redirects traffic coming from specific ports to server Rule */

		char* ports_string = "";

		for (long port_count = 0; port_count < px_handler->px_opt->nrd_ports; \
		port_count++) {
			if (port_count == px_handler->px_opt->nrd_ports - 1) {
				ports_string = strappend(2, ports_string, \
						px_handler->px_opt->rd_ports[port_count]);
			}
			else {
				ports_string = strappend(3, ports_string, \
						px_handler->px_opt->rd_ports[port_count], ",");
			}
		}


		if (px_handler->pxl_server->type == SOCK_STREAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_DELETE, FIREWALL_CONSTANT_TCP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION, \
					ports_string, FIREWALL_CONSTANT_TARGET_DNAT, FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION, \
					strappend(3, px_handler->pxl_server->hostip, ":", px_handler->pxl_server->port), NULL);
		}
		else if (px_handler->pxl_server->type == SOCK_DGRAM) {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_DELETE, FIREWALL_CONSTANT_UDP_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION, \
					ports_string, FIREWALL_CONSTANT_TARGET_DNAT, FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION, \
					strappend(3, px_handler->pxl_server->hostip, ":", px_handler->pxl_server->port), NULL);

		}
		else {
			execute_rule(FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_PROGRAM, FIREWALL_CONSTANT_NAT_TABLE, \
					FIREWALL_CONSTANT_DELETE, FIREWALL_CONSTANT_ALL_PROTOCOL, FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION, \
					ports_string, FIREWALL_CONSTANT_TARGET_DNAT, FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION, \
					strappend(3, px_handler->pxl_server->hostip, ":", px_handler->pxl_server->port), NULL);
		}
	}

	return PROXY_ERROR_NONE;
}
