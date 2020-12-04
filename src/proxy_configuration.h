/* proxy_configuration.c declaration.

Copyright (C) 2020  Mohith Reddy

Proxifier is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proxifier is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>. */

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

int free_config_state(struct config_state** _conf_state);

#endif /* SRC_PROXY_CONFIGURATION_H_ */
