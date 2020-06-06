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
#include "proxy_structures.h"
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
	char* hname;
	uint16_t qtype;
	uint32_t qclass;
};

struct dns_rrecord {
	void* name;
	unsigned int name_len;
	char* hname;
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

int dump_dns_header(struct dns_header* dns_hdr, struct proxy_data* dns_data, unsigned long* bit_start);

int dump_dns_question(struct dns_question* dns_ques, struct proxy_data* dns_data, unsigned long* bit_start);

int dump_dns_rrecord(struct dns_rrecord* dns_record, struct proxy_data* dns_data, unsigned long* bit_start);

struct proxy_data* create_dns_msg(struct dns_msg* dns_msg, int cd_flags);

int parse_dns_header(struct proxy_data* dns_data, struct dns_header* dns_hdr, unsigned long *bit_start);

int parse_dns_question(struct proxy_data* dns_data, struct dns_question* dns_ques, unsigned long *bit_start);

int parse_dns_rrecord(struct proxy_data* dns_data, struct dns_rrecord* dns_record, unsigned long* bit_start);

struct dns_msg* parse_dns_msg(struct proxy_data* dns_data, int pd_flags);

int domain_to_host(struct proxy_data* dns_data, unsigned long *bit_start, char** _hname);

struct proxy_data* host_to_domain(char* hostname);

#endif /* SRC_DNS_H_ */
