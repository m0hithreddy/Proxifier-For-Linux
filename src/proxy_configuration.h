/*
 * proxy_configuration.h
 *
 *  Created on: 28-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_PROXY_CONFIGURATION_H_
#define SRC_PROXY_CONFIGURATION_H_

#define HTTP_PROXY_CONFIGURATION_OPTIONS " http_proxy_method_get \
http_proxy_method_connect "

#define PROXY_DEFAULT_CONFIG_FILE "/usr/local/etc/proxifier.conf"

#include "proxy.h"
#include "proxy_structures.h"

struct config_state {
	int start;
	struct proxy_handler* px_handler;
	int end;
};

int get_proxy_handlers(char* config_file, struct proxy_bag* rc_results);

int fill_proxy_handler(char* conf_key, char* conf_value, struct config_state* conf_state);

int validate_proxy_handler(struct proxy_handler* px_handler);

#endif /* SRC_PROXY_CONFIGURATION_H_ */
