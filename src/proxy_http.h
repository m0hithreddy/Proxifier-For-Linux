/*
 * proxy_http.h
 *
 *  Created on: 16-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_PROXY_HTTP_H_
#define SRC_PROXY_HTTP_H_

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_
#include "config.h"
#endif

#define PROXY_DEFAULT_HTTP_USER_AGENT PACKAGE_NAME"/"PACKAGE_VERSION
#define PROXY_DEFAULT_HTTP_PROXY_AUTHORIZATION_SCHEME "basic"

#include "proxy.h"
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

struct http_data {
	int protocol;
	int* get_ports;
	int n_get_ports;
	int* connect_ports;
	int n_connect_ports;
	char* authpass;
};

void* http_proxy_init(void* _px_handler);

void* http_proxy_handler(void* _px_request);

int fill_http_proxy_handler(char* conf_key, char* conf_value, struct proxy_handler* px_handler);

int validate_http_proxy_handler(struct proxy_handler* px_handler);

int free_http_proxy_handler(struct proxy_handler* px_handler);

int fill_http_proxy_request(struct proxy_handler* px_handler, struct proxy_request* px_request);

int free_http_proxy_request(struct proxy_request* px_request);

#endif /* SRC_PROXY_HTTP_H_ */
