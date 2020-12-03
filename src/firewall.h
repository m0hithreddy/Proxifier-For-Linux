/* firewall.c declarations

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

#include "proxy.h"

int config_fwall(struct proxy_handler* px_handler);

int deconfig_fwall(struct proxy_handler* px_request);

#endif /* SRC_FIREWALL_H_ */
