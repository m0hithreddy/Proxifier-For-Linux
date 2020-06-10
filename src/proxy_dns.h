/*
 * proxy_dns.h
 *
 *  Created on: 31-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_PROXY_DNS_H_
#define SRC_PROXY_DNS_H_

#define PROXY_DNS_RESPONSE_DEFAULT_TTL 30

#include "proxy.h"
#include <netinet/in.h>

void* dns_proxy_init(void* _px_handler);

int dns_proxy_handler(int sockfd);

int validate_dns_proxy_handler(struct proxy_handler* px_handler);

struct dns_msg* proxy_dns_response(struct dns_msg* dns_query);

char* proxy_dns_resolve(char* hostname);

#endif /* SRC_PROXY_DNS_H_ */
