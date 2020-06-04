/*
 * dns.h
 *
 *  Created on: 03-Jun-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_DNS_H_
#define SRC_DNS_H_

#define DNS_TRANSACTION_SIZE 512
#define DNS_HEADER_SIZE 12

#define DNS_MODE_PARTIAL 0b1
#define DNS_MODE_COMPLETE 0b0

#include "bit.h"
#include <stdint.h>

struct dns_header {
	uint16_t id;
	bit qr[1];
	bit opcode[4];
	bit aa[1];
	bit tc[1];
	bit rd[1];
	bit ra[1];
	bit z[3];
	bit rcode[4];
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct dns_question {
	void* qname;
	unsigned int qname_len;
	char* dname;
	uint16_t qtype;
	uint32_t qclass;
};

struct dns_rrecord {
	void* name;
	unsigned int name_len;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	void* rdata;
};

struct dns_msg {
	struct dns_header* header;
	struct dns_question* question;
	uint16_t qdcount;
	struct dns_rrecord* answer;
	uint16_t ancount;
	struct dns_rrecord* authority;
	uint16_t nscount;
	struct dns_rrecord* additional;
	uint16_t arcount;
};

struct proxy_data* create_dns_response(struct dns_msg* dns_response, int cd_flags);

struct dns_msg* parse_dns_query(struct proxy_data* dns_data, int pd_flags);

#endif /* SRC_DNS_H_ */
