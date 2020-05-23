/*
 * proxy_http.h
 *
 *  Created on: 16-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_PROXY_HTTP_H_
#define SRC_PROXY_HTTP_H_

#define PROXY_DEFAULT_HTTP_USER_AGENT "PROXIFIER/1.0"
#define PROXY_DEFAULT_HTTP_PROXY_AUTHORIZATION_SCHEME "basic"
#include "proxy.h"
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

void* http_proxy_init(void* _px_handler);

void* http_proxy_handler(void* _px_request);

int http_data_setup(struct proxy_handler* px_handler, void** _http_data);

int http_data_free(void** _http_data);

#endif /* SRC_PROXY_HTTP_H_ */
