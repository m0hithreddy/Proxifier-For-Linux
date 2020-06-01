/*
 * firewall.h
 *
 *  Created on: 22-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_FIREWALL_H_
#define SRC_FIREWALL_H_

#define FIREWALL_CONSTANT_PROGRAM "iptables"
#define FIREWALL_CONSTANT_NAT_TABLE "--table", "nat"
#define FIREWALL_CONSTANT_INSERT_AT_TOP "--insert", "OUTPUT", "1"
#define FIREWALL_CONSTANT_INSERT_AT_BOTTOM "--append", "OUTPUT"
#define FIREWALL_CONSTANT_DELETE "--delete", "OUTPUT"
#define FIREWALL_CONSTANT_ALL_PROTOCOL "--protocol", "all"
#define FIREWALL_CONSTANT_TCP_PROTOCOL "--protocol", "tcp"
#define FIREWALL_CONSTANT_UDP_PROTOCOL "--protocol", "udp"
#define FIREWALL_CONSTANT_DESTINATION_ADRESS_OPTION "--destination"
#define FIREWALL_CONSTANT_DESTINATION_PORTS_OPTION "--match", "multiport", "--destination-ports"
#define FIREWALL_CONSTANT_TARGET_ACCEPT "--jump", "ACCEPT"
#define FIREWALL_CONSTANT_TARGET_DNAT "--jump", "DNAT"
#define FIREWALL_CONSTANT_REDIRECTION_ADDRESS_OPTION "--to-destination"

#define execute_rule(file, ...)\
	do{\
		pthread_mutex_lock(&fwall_lock);\
		sigset_t sigmask = *(px_handler->px_opt->sigmask);\
		sigaddset(&sigmask, SIGCHLD);\
		pid_t fk_return = fork();\
		if (fk_return < 0) {\
			pthread_mutex_unlock(&fwall_lock);\
			return PROXY_ERROR_FATAL;\
		}\
		else if (fk_return == 0) {\
			execlp(file, ##__VA_ARGS__);\
		}\
		int signo;\
		if (sigwait(&sigmask, &signo) != 0) {\
			pthread_mutex_unlock(&fwall_lock);\
			return PROXY_ERROR_FATAL;\
		}\
		if (signo != SIGCHLD) {\
			pthread_mutex_unlock(&fwall_lock);\
			return PROXY_ERROR_SIGRCVD;\
		}\
		int wstatus;\
		if (waitpid(fk_return, &wstatus, 0) != fk_return) {\
			pthread_mutex_unlock(&fwall_lock);\
			return PROXY_ERROR_FATAL;\
		}\
		if (WIFEXITED(wstatus) != true || WEXITSTATUS(wstatus) != 0) {\
			pthread_mutex_unlock(&fwall_lock);\
			return PROXY_ERROR_FATAL;\
		}\
		pthread_mutex_unlock(&fwall_lock);\
	}while(0)

#include "proxy.h"

int config_fwall(struct proxy_handler* px_handler);

int deconfig_fwall(struct proxy_handler* px_request);

#endif /* SRC_FIREWALL_H_ */
