/*
 * dns.c
 *
 *  Created on: 03-Jun-2020
 *      Author: Mohith Reddy
 */

#include "dns.h"
#include "bit.h"
#include "proxy_functions.h"
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

struct proxy_data* create_dns_response(struct dns_msg* dns_response, int cd_flags)
{
	if (dns_response == NULL || dns_response->header == NULL) {
		return NULL;
	}

	/* Initialize the proxy_data{} */

	struct proxy_data* dns_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	dns_data->data = calloc(1, DNS_TRANSACTION_SIZE);

	unsigned long bit_count = 0, data_size = DNS_TRANSACTION_SIZE * 8;

	/* Dump DNS header */

		/* DNS transaction ID */

	if (data_size < bit_count + 16)
		goto create_error;

	int_to_bitarray(dns_response->header->id, dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* QR flag */

	if (data_size < bit_count + 1)
		goto create_error;

	if (dns_response->header->qr[0] > 0)
		set_bit(dns_data->data, bit_count);

	bit_count++;

		/* OPcode */

	if (data_size < bit_count + 4)
		goto create_error;

	for (int i = 0; i < 4; i++) {
		if (dns_response->header->opcode[i] > 0)
			set_bit(dns_data->data, bit_count + i);
	}

	bit_count = bit_count + 4;

		/* AA flag */

	if (data_size < bit_count + 1)
		goto create_error;

	if (dns_response->header->aa[0] > 0)
		set_bit(dns_data->data, bit_count);

	bit_count++;

		/* TC flag */

	if (data_size < bit_count + 1)
		goto create_error;

	if (dns_response->header->tc[0] > 0)
		set_bit(dns_data->data, bit_count);

	bit_count++;

		/* RD flag */

	if (data_size < bit_count + 1)
		goto create_error;

	if (dns_response->header->rd[0] > 0)
		set_bit(dns_data->data, bit_count);

	bit_count++;

		/* RA flag */

	if (data_size < bit_count + 1)
		goto create_error;

	if (dns_response->header->ra[0] > 0)
		set_bit(dns_data->data, bit_count);

	bit_count++;

		/* Z */

	if (data_size < bit_count + 3)
		goto create_error;

	for (int i = 0; i < 3; i++) {
		if (dns_response->header->z[i] > 0)
			set_bit(dns_data->data, bit_count);
	}

	bit_count = bit_count + 3;

		/* Rcode */

	if (data_size < bit_count + 4)
		goto create_error;

	for (int i = 0; i < 4; i++) {
		if (dns_response->header->rcode[i] > 0)
			set_bit(dns_data->data, bit_count + i);
	}

	bit_count = bit_count + 4;

		/* QDcount */

	if (data_size < bit_count + 16)
		goto create_error;

	int_to_bitarray(dns_response->header->qdcount, dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* ANcount */

	if (data_size < bit_count + 16)
		goto create_error;

	int_to_bitarray(dns_response->header->ancount, dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* NScount */

	if (data_size < bit_count + 16)
		goto create_error;

	int_to_bitarray(dns_response->header->nscount, dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* ARcount */

	if (data_size < bit_count + 16)
		goto create_error;

	int_to_bitarray(dns_response->header->arcount, dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

	/* Dump DNS answer resource records */

	if (dns_response->header->qr[0] != 1 || dns_response->header->ancount == 0)
		return dns_data;

	if (dns_response->answer == NULL || dns_response->ancount == 0)
		goto create_error;

	for (unsigned int ans_count = 0; ans_count < dns_response->ancount; ans_count++) {
		/* Name */

		if (data_size < bit_count + dns_response->answer[ans_count].name_len * 8)
			goto create_error;

		memcpy(dns_data->data + bit_count / 8, dns_response->answer[ans_count].name, \
				dns_response->answer[ans_count].name_len);

		bit_count = bit_count + dns_response->answer[ans_count].name_len * 8;

		/* Type */

		if (data_size < bit_count + 16)
			goto create_error;

		int_to_bitarray(dns_response->answer[ans_count].type, dns_data->data, bit_count, 16);
		bit_count = bit_count + 16;

		/* Class */

		if (data_size < bit_count + 16)
			goto create_error;

		int_to_bitarray(dns_response->answer[ans_count].class, dns_data->data, bit_count, 16);
		bit_count = bit_count + 16;

		/* TTL */

		if (data_size < bit_count + 32)
			goto create_error;

		int_to_bitarray(dns_response->answer[ans_count].ttl, dns_data->data, bit_count, 32);
		bit_count = bit_count + 32;

		/* RDlength */

		if (data_size < bit_count + 16)
			goto create_error;

		int_to_bitarray(dns_response->answer[ans_count].rdlength, dns_data->data, bit_count, 16);
		bit_count = bit_count + 16;

		/* RDATA */

		if (data_size < bit_count + dns_response->answer[ans_count].rdlength * 8)
			goto create_error;

		memcpy(dns_data->data + bit_count / 8, dns_response->answer[ans_count].rdata, \
				dns_response->answer[ans_count].rdlength);

		bit_count = bit_count + dns_response->answer[ans_count].rdlength * 8;
	}

	if (dns_response->ancount < dns_response->header->ancount)
		goto create_error;

	dns_data->size = bit_count / 8 + (bit_count % 8 > 0 ? 1 : 0);

	return dns_data;

	create_error:

	if (cd_flags & DNS_MODE_PARTIAL) {
		dns_data->size = bit_count / 8 + (bit_count % 8 > 0 ? 1 : 0);
		return dns_data;
	}

	return NULL;
}

struct dns_msg* parse_dns_query(struct proxy_data* dns_data, int pd_flags)
{
	if (dns_data == NULL || dns_data->data == NULL || dns_data->size <= 0)
		return NULL;

	struct dns_msg* dns_query = calloc(1, sizeof(struct dns_msg));
	unsigned long bit_count = 0, data_size = dns_data->size * 8;

	/* Fill DNS header */

	dns_query->header = (struct dns_header*) calloc(1, sizeof(struct dns_header));

		/* DNS transaction ID */

	if (bit_count + 16 > data_size)
		goto parse_error;

	dns_query->header->id = bitarray_to_int(dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* QR flag */

	if (bit_count + 1 > data_size)
		goto parse_error;

	dns_query->header->qr[0] = get_bit(dns_data->data, bit_count);
	bit_count++;

		/* OPcode */

	if (bit_count + 4 > data_size)
		goto parse_error;

	for (int i = 0; i < 4; i++) {
		dns_query->header->opcode[i] = get_bit(dns_data->data, bit_count + i);
	}
	bit_count = bit_count + 4;

		/* AA flag */

	if (bit_count + 1 > data_size)
		goto parse_error;

	dns_query->header->aa[0] = get_bit(dns_data->data, bit_count);
	bit_count++;

		/* TC flag */

	if (bit_count + 1 > data_size)
		goto parse_error;

	dns_query->header->tc[0] = get_bit(dns_data->data, bit_count);
	bit_count++;

		/* RD flag */

	if (bit_count + 1 > data_size)
		goto parse_error;

	dns_query->header->rd[0] = get_bit(dns_data->data, bit_count);
	bit_count++;

		/* RA flag */

	if (bit_count + 1 > data_size)
		goto parse_error;

	dns_query->header->ra[0] = get_bit(dns_data->data, bit_count);
	bit_count++;

		/* Z */

	if (bit_count + 3 > data_size)
		goto parse_error;

	for (int i = 0; i < 3; i++) {
		dns_query->header->z[i] = get_bit(dns_data->data, bit_count + i);
	}
	bit_count = bit_count + 3;

		/* Rcode */

	if (bit_count + 4 > data_size)
		goto parse_error;

	for (int i = 0; i < 4; i++) {
		dns_query->header->rcode[i] = get_bit(dns_data->data, bit_count + i);
	}
	bit_count = bit_count + 4;

		/* QDcount */

	if (bit_count + 16 > data_size)
		goto parse_error;

	dns_query->header->qdcount = bitarray_to_int(dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* ANcount */

	if (bit_count + 16 > data_size)
		goto parse_error;

	dns_query->header->ancount = bitarray_to_int(dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* NScount */

	if (bit_count + 16 > data_size)
		goto parse_error;

	dns_query->header->nscount = bitarray_to_int(dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

		/* ARcount */

	if (bit_count + 16 > data_size)
		goto parse_error;

	dns_query->header->arcount = bitarray_to_int(dns_data->data, bit_count, 16);
	bit_count = bit_count + 16;

	/* DNS questions */

	if (dns_query->header->qr[0] != 0 || dns_query->header->qdcount == 0)
		return dns_query;

	dns_query->question = (struct dns_question*) calloc(dns_query->header->qdcount, sizeof(struct dns_question));
	dns_query->qdcount = dns_query->header->qdcount;

	for (int ques_count = 0; ques_count < dns_query->qdcount; ques_count++) {
		/* Parse the DNS Question format */

			/* Extract the Qname from the question */

		int ques_start = bit_count, cur_bit = bit_count, add_flag = 1;

		dns_query->question[ques_count].dname = (char*) calloc(1, sizeof(char));

		for ( ; ; ) {
			if (cur_bit + 2 > data_size)
				goto parse_error;

			int type = bitarray_to_int(dns_data->data, cur_bit, 2);
			cur_bit = cur_bit + 2;
			if (add_flag)
				bit_count = cur_bit;

			if (type == 0) {
				if (cur_bit + 6 > data_size)
					goto parse_error;

				int label_len = bitarray_to_int(dns_data->data, cur_bit, 6);
				cur_bit = cur_bit + 6;
				if (add_flag)
					bit_count = cur_bit;

				if (label_len == 0)
					break;

				for (int label_count = 0; label_count < label_len; label_count++) {
					if (cur_bit + 8 > data_size)
						goto parse_error;

					char ch[2];
					ch[1] = '\0';

					ch[0] = bitarray_to_int(dns_data->data, cur_bit, 8);
					cur_bit = cur_bit + 8;
					if (add_flag)
						bit_count = cur_bit;

					dns_query->question->dname = strappend(2, dns_query->question->dname, ch);
				}

				dns_query->question->dname = strappend(2, dns_query->question->dname, ".");
			}
			else if (type == 3) {
				if (cur_bit + 14 > data_size)
					goto parse_error;

				cur_bit = bitarray_to_int(dns_data->data, cur_bit, 14);
				if (add_flag) {
					bit_count = bit_count + 14;
					add_flag = 0;
				}
			}
			else
				return NULL;
		}

		dns_query->question[ques_count].qname = memndup(dns_data->data + ques_start / 8, (bit_count - ques_start) / 8);
		dns_query->question[ques_count].qname_len = (bit_count - ques_start) / 8;

			/* Qtype */

		if (bit_count + 16 > data_size)
			goto parse_error;

		dns_query->question[ques_count].qtype =  bitarray_to_int(dns_data->data, bit_count, 16);
		bit_count = bit_count + 16;

			/* Qclass */

		if (bit_count + 16 > data_size)
			goto parse_error;

		dns_query->question[ques_count].qclass = bitarray_to_int(dns_data->data, bit_count, 16);
		bit_count = bit_count + 16;
	}

	return dns_query;

	parse_error:

	if (pd_flags & DNS_MODE_PARTIAL)
		return dns_query;

	return NULL;
}

struct proxy_data* host_to_domain(char* hostname)
{
	if (hostname == NULL)
		return NULL;

	/* Initialize the domain_data{} */

	struct proxy_data* domain_data = (struct proxy_data*) calloc(1, \
			sizeof(struct proxy_data));

	/* If an empty hostname is given */

	if (*hostname == '\0') {
		domain_data->data = calloc(1, 1);
		domain_data->size = 1;

		return domain_data;
	}

	/* Initialize the domain_data->data */

	unsigned int hname_len = strlen(hostname);

	domain_data->data = calloc(1, hname_len + 2);
	uint8_t* domain_name = (uint8_t*) domain_data->data;

	/* Loop by label and convert them into domain format */

	unsigned int dname_count = 0, hname_count = 0, label_len = 0;
	char* dot_ptr = NULL;

	for ( ; hname_count < hname_len; ) {
		/* Calculate the "." position and compute the label length */

		dot_ptr = strstr(hostname + hname_count, ".");

		if (dot_ptr == NULL)
			label_len = hname_len - hname_count;
		else
			label_len = (long) (dot_ptr - hostname - hname_count);

		if (label_len > 63)
			return NULL;

		/* Copy the label characters */

		domain_name[dname_count] = label_len;
		dname_count++;

		strncpy(domain_name + dname_count, hostname + hname_count, label_len);
		hname_count = hname_count + label_len + 1;
		dname_count = dname_count + label_len;
	}

	/* The ending label */

	domain_name[dname_count] = 0;
	dname_count++;

	/* Return the domain_data{} */

	domain_data->size = dname_count;

	return domain_data;
}
