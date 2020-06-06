/*
 * dns.c
 *
 *  Created on: 03-Jun-2020
 *      Author: Mohith Reddy
 */

#include "dns.h"
#include "bit.h"
#include "proxy_functions.h"
#include "proxy.h"
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

int dump_dns_header(struct dns_header* dns_hdr, struct proxy_data* dns_data, unsigned long* bit_start)
{
	if (dns_hdr == NULL || dns_data == NULL || dns_data->data == NULL || \
			dns_data->size <= 0 || bit_start == NULL) {
		return PROXY_ERROR_INVAL;
	}

	/* Dump DNS header */

	unsigned long _bit_start = *bit_start, data_size = dns_data->size * 8;

		/* DNS transaction ID */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_hdr->id, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* QR flag */

	if (data_size < _bit_start + 1)
		return PROXY_ERROR_RETRY;

	if (dns_hdr->qr[0] > 0)
		set_bit(dns_data->data, _bit_start);
	else
		clear_bit(dns_data->data, _bit_start);

	_bit_start++;

		/* OPcode */

	if (data_size < _bit_start + 4)
		return PROXY_ERROR_RETRY;

	for (int i = 0; i < 4; i++) {
		if (dns_hdr->opcode[i] > 0)
			set_bit(dns_data->data, _bit_start + i);
		else
			clear_bit(dns_data->data, _bit_start + i);
	}

	_bit_start = _bit_start + 4;

		/* AA flag */

	if (data_size < _bit_start + 1)
		return PROXY_ERROR_RETRY;

	if (dns_hdr->aa[0] > 0)
		set_bit(dns_data->data, _bit_start);
	else
		clear_bit(dns_data->data, _bit_start);

	_bit_start++;

		/* TC flag */

	if (data_size < _bit_start + 1)
		return PROXY_ERROR_RETRY;

	if (dns_hdr->tc[0] > 0)
		set_bit(dns_data->data, _bit_start);
	else
		clear_bit(dns_data->data, _bit_start);

	_bit_start++;

		/* RD flag */

	if (data_size < _bit_start + 1)
		return PROXY_ERROR_RETRY;

	if (dns_hdr->rd[0] > 0)
		set_bit(dns_data->data, _bit_start);
	else
		clear_bit(dns_data->data, _bit_start);

	_bit_start++;

		/* RA flag */

	if (data_size < _bit_start + 1)
		return PROXY_ERROR_RETRY;

	if (dns_hdr->ra[0] > 0)
		set_bit(dns_data->data, _bit_start);
	else
		clear_bit(dns_data->data, _bit_start);

	_bit_start++;

		/* Z */

	if (data_size < _bit_start + 3)
		return PROXY_ERROR_RETRY;

	for (int i = 0; i < 3; i++) {
		if (dns_hdr->z[i] > 0)
			set_bit(dns_data->data, _bit_start);
		else
			clear_bit(dns_data->data, _bit_start);
	}

	_bit_start = _bit_start + 3;

		/* Rcode */

	if (data_size < _bit_start + 4)
		return PROXY_ERROR_RETRY;

	for (int i = 0; i < 4; i++) {
		if (dns_hdr->rcode[i] > 0)
			set_bit(dns_data->data, _bit_start + i);
		else
			clear_bit(dns_data->data, _bit_start + i);
	}

	_bit_start = _bit_start + 4;

		/* QDcount */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_hdr->qdcount, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* ANcount */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_hdr->ancount, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* NScount */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_hdr->nscount, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* ARcount */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_hdr->arcount, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Return success */

	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
}

int dump_dns_question(struct dns_question* dns_ques, struct proxy_data* dns_data, unsigned long* bit_start)
{
	if (dns_ques == NULL || dns_data == NULL || dns_data->data == NULL || \
			dns_data->size <= 0 || bit_start == NULL) {
		return PROXY_ERROR_INVAL;
	}

	/* Dump DNS Question */

	unsigned long _bit_start = *bit_start, data_size = dns_data->size * 8;

	/* QNAME */

	if (data_size < _bit_start + dns_ques->qname_len * 8)
		return PROXY_ERROR_RETRY;

	memcpy(dns_data->data + _bit_start / 8, dns_ques->qname, dns_ques->qname_len);
	_bit_start = _bit_start + dns_ques->qname_len * 8;

	/* QTYPE */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_ques->qtype, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* QCLASS */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_ques->qclass, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Return success */

	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
}

int dump_dns_rrecord(struct dns_rrecord* dns_record, struct proxy_data* dns_data, unsigned long* bit_start)
{
	if (dns_record == NULL || dns_data == NULL || dns_data->data == NULL || \
			dns_data->size <= 0 || bit_start == NULL) {
		return PROXY_ERROR_INVAL;
	}

	/* Dump DNS Resource Record */

	unsigned long _bit_start = *bit_start, data_size = dns_data->size * 8;

	/* Name */

	if (data_size < _bit_start + dns_record->name_len * 8)
		return PROXY_ERROR_RETRY;

	memcpy(dns_data->data + _bit_start / 8, dns_record->name, dns_record->name_len);

	_bit_start = _bit_start + dns_record->name_len * 8;

	/* Type */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_record->type, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Class */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_record->class, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* TTL */

	if (data_size < _bit_start + 32)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_record->ttl, dns_data->data, _bit_start, 32);
	_bit_start = _bit_start + 32;

	/* RDlength */

	if (data_size < _bit_start + 16)
		return PROXY_ERROR_RETRY;

	int_to_bitarray(dns_record->rdlength, dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* RDATA */

	if (data_size < _bit_start + dns_record->rdlength * 8)
		return PROXY_ERROR_RETRY;

	memcpy(dns_data->data + _bit_start / 8, dns_record->rdata, \
			dns_record->rdlength);

	_bit_start = _bit_start + dns_record->rdlength * 8;

	/* Return success */

	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
}

struct proxy_data* create_dns_msg(struct dns_msg* dns_msg, int cd_flags)
{
	if (dns_msg == NULL || dns_msg->header == NULL) {
		return NULL;
	}

	/* Initialize the dns_data{} */

	struct proxy_data* dns_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	dns_data->data = calloc(1, DNS_TRANSACTION_SIZE);
	dns_data->size = DNS_TRANSACTION_SIZE;

	unsigned long bit_count = 0;

	int dump_return = PROXY_ERROR_NONE;

	/* Dump DNS Header */

	dump_return = dump_dns_header(dns_msg->header, dns_data, &bit_count);

	if (dump_return == PROXY_ERROR_FATAL)
		return NULL;
	else if (dump_return != PROXY_ERROR_NONE)
		goto create_error;

	/* Dump DNS Questions */

	if (dns_msg->qdcount > 0) {
		for (unsigned int ques_count = 0; ques_count < dns_msg->qdcount; ques_count++) {
			dump_return = dump_dns_question(dns_msg->question + ques_count, dns_data, \
					&bit_count);

			if (dump_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (dump_return != PROXY_ERROR_NONE)
				goto create_error;
		}
	}

	/* Dump DNS Answers */

	if (dns_msg->ancount > 0) {
		for (unsigned int an_count = 0; an_count < dns_msg->ancount; an_count++) {
			dump_return = dump_dns_rrecord(dns_msg->answer + an_count, dns_data, \
					&bit_count);

			if (dump_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (dump_return != PROXY_ERROR_NONE)
				goto create_error;
		}
	}

	/* Dump DNS Authority */

	if (dns_msg->nscount > 0) {
		for (unsigned int ns_count = 0; ns_count < dns_msg->nscount; ns_count++) {
			dump_return = dump_dns_rrecord(dns_msg->authority + ns_count, dns_data, \
					&bit_count);

			if (dump_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (dump_return != PROXY_ERROR_NONE)
				goto create_error;
		}
	}

	/* Dump DNS Additional */

	if (dns_msg->arcount > 0) {
		for (unsigned int ar_count = 0; ar_count < dns_msg->arcount; ar_count++) {
			dump_return = dump_dns_rrecord(dns_msg->additional + ar_count, dns_data, \
					&bit_count);

			if (dump_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (dump_return != PROXY_ERROR_NONE)
				goto create_error;
		}
	}

	/* Return success */

	dns_data->size = bit_count / 8 + (bit_count % 8 > 0 ? 1 : 0);

	return dns_data;

	create_error:

	if (cd_flags & DNS_MODE_PARTIAL) {
		dns_data->size = bit_count / 8 + (bit_count % 8 > 0 ? 1 : 0);
		return dns_data;
	}

	return NULL;
}

int parse_dns_header(struct proxy_data* dns_data, struct dns_header* dns_hdr, unsigned long *bit_start)
{
	if (dns_data == NULL || dns_data->data == NULL || dns_data->size <= 0 || \
			bit_start == NULL || dns_hdr == NULL) {
		return PROXY_ERROR_INVAL;
	}

	unsigned long _bit_start = *bit_start, data_size = dns_data->size * 8;

	/* Parse the DNS header */

		/* DNS transaction ID */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->id = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* QR flag */

	if (_bit_start + 1 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->qr[0] = get_bit(dns_data->data, _bit_start);
	_bit_start++;

		/* OPcode */

	if (_bit_start + 4 > data_size)
		return PROXY_ERROR_RETRY;

	for (int i = 0; i < 4; i++) {
		dns_hdr->opcode[i] = get_bit(dns_data->data, _bit_start + i);
	}
	_bit_start = _bit_start + 4;

		/* AA flag */

	if (_bit_start + 1 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->aa[0] = get_bit(dns_data->data, _bit_start);
	_bit_start++;

		/* TC flag */

	if (_bit_start + 1 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->tc[0] = get_bit(dns_data->data, _bit_start);
	_bit_start++;

		/* RD flag */

	if (_bit_start + 1 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->rd[0] = get_bit(dns_data->data, _bit_start);
	_bit_start++;

		/* RA flag */

	if (_bit_start + 1 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->ra[0] = get_bit(dns_data->data, _bit_start);
	_bit_start++;

		/* Z */

	if (_bit_start + 3 > data_size)
		return PROXY_ERROR_RETRY;

	for (int i = 0; i < 3; i++) {
		dns_hdr->z[i] = get_bit(dns_data->data, _bit_start + i);
	}
	_bit_start = _bit_start + 3;

		/* Rcode */

	if (_bit_start + 4 > data_size)
		return PROXY_ERROR_RETRY;

	for (int i = 0; i < 4; i++) {
		dns_hdr->rcode[i] = get_bit(dns_data->data, _bit_start + i);
	}
	_bit_start = _bit_start + 4;

		/* QDcount */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->qdcount = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* ANcount */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->ancount = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* NScount */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->nscount = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

		/* ARcount */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_hdr->arcount = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Return success */

	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
}

int parse_dns_question(struct proxy_data* dns_data, struct dns_question* dns_ques, unsigned long *bit_start)
{
	if (dns_data == NULL || dns_data->data == NULL || dns_data->size <= 0 || \
			bit_start ==  NULL || dns_ques == NULL) {
		return PROXY_ERROR_INVAL;
	}

	/* Parse the DNS Question */

	/* Extract the Qname from the question */

	unsigned long ques_start = *bit_start, _bit_start = *bit_start, \
			data_size = dns_data->size * 8;

	int dh_return = domain_to_host(dns_data, &_bit_start, &(dns_ques->hname));

	if (dh_return != PROXY_ERROR_NONE)
		return dh_return;

	dns_ques->qname = memndup(dns_data->data + ques_start / 8, \
			(_bit_start - ques_start) / 8);
	dns_ques->qname_len = (_bit_start - ques_start) / 8;

	/* Qtype */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_ques->qtype =  bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Qclass */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_ques->qclass = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Return success */

	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
}

int parse_dns_rrecord(struct proxy_data* dns_data, struct dns_rrecord* dns_record, unsigned long* bit_start)
{
	if (dns_data == NULL || dns_data->data == NULL || dns_data->size <= 0 || \
			bit_start == NULL || dns_record == NULL) {
		return PROXY_ERROR_INVAL;
	}

	/* Parse DNS Resource Records */

	/* Extract the name */

	unsigned long ans_start = *bit_start, _bit_start = *bit_start, \
			data_size = dns_data->size * 8;

	int dh_return = domain_to_host(dns_data, &_bit_start, \
			& (dns_record->hname));

	if (dh_return != PROXY_ERROR_NONE)
		return dh_return;

	dns_record->name = memndup(dns_data->data + _bit_start / 8, \
			(_bit_start - ans_start) / 8);
	dns_record->name_len = (_bit_start - ans_start) / 8;

	/* Type */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_record->type = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* Class */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_record->type = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* TTL */

	if (_bit_start + 32 > data_size)
		return PROXY_ERROR_RETRY;

	dns_record->ttl = bitarray_to_int(dns_data->data, _bit_start, 32);
	_bit_start = _bit_start + 32;

	/* RDLENGTH */

	if (_bit_start + 16 > data_size)
		return PROXY_ERROR_RETRY;

	dns_record->rdlength = bitarray_to_int(dns_data->data, _bit_start, 16);
	_bit_start = _bit_start + 16;

	/* RDATA */

	if (_bit_start + dns_record->rdlength > data_size)
		return PROXY_ERROR_RETRY;

	dns_record->rdata = memndup(dns_data->data + _bit_start / 8, dns_record->rdlength);
	_bit_start = _bit_start + dns_record->rdlength;

	/* Return success */

	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
}

struct dns_msg* parse_dns_msg(struct proxy_data* dns_data, int pd_flags)
{
	if (dns_data == NULL || dns_data->data == NULL || dns_data->size <= 0)
		return NULL;

	struct dns_msg* dns_msg = calloc(1, sizeof(struct dns_msg));
	unsigned long bit_count = 0;
	int parse_return = PROXY_ERROR_NONE;

	/* Parse DNS header */

	dns_msg->header = (struct dns_header*) calloc(1, sizeof(struct dns_header));

	parse_return = parse_dns_header(dns_data, dns_msg->header, &bit_count);

	if (parse_return == PROXY_ERROR_FATAL)
		return NULL;
	else if (parse_return != PROXY_ERROR_NONE)
		goto parse_error;

	/* Questions */

	if (dns_msg->header->qdcount > 0) {
		/* Allocate memory */

		dns_msg->question = (struct dns_question*) calloc(dns_msg->header->qdcount, \
				sizeof(struct dns_question));
		dns_msg->qdcount = dns_msg->header->qdcount;

		/* Parse the DNS questions */

		for (unsigned int ques_count = 0; ques_count < dns_msg->qdcount; ques_count++) {
			parse_return = parse_dns_question(dns_data, dns_msg->question + ques_count, &bit_count);

			if (parse_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (parse_return != PROXY_ERROR_NONE)
				goto parse_error;
		}
	}

	/* Answers */

	if (dns_msg->header->ancount > 0) {
		/* Allocate Memory */

		dns_msg->answer = (struct dns_rrecord*) calloc(dns_msg->header->ancount, \
				sizeof(struct dns_rrecord));
		dns_msg->ancount = dns_msg->header->ancount;

		/* Parse DNS Answer Records */

		for (unsigned int ans_count = 0; ans_count < dns_msg->header->ancount; ans_count++) {
			parse_return = parse_dns_rrecord(dns_data, dns_msg->answer + ans_count, &bit_count);

			if (parse_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (parse_return != PROXY_ERROR_NONE)
				goto parse_error;
		}
	}

	/* Authorities */

	if (dns_msg->header->nscount > 0) {
		/* Allocate Memory */

		dns_msg->authority = (struct dns_rrecord*) calloc(dns_msg->header->nscount, \
				sizeof(struct dns_rrecord));
		dns_msg->nscount = dns_msg->header->nscount;

		/* Parse DNS Authority Records */

		for (unsigned int ns_count = 0; ns_count < dns_msg->header->nscount; ns_count++) {
			parse_return = parse_dns_rrecord(dns_data, dns_msg->authority + ns_count, &bit_count);

			if (parse_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (parse_return != PROXY_ERROR_NONE)
				goto parse_error;
		}
	}

	/* Additional */

	if (dns_msg->header->arcount > 0) {
		/* Allocate Memory */

		dns_msg->additional = (struct dns_rrecord*) calloc(dns_msg->header->arcount, \
				sizeof(struct dns_rrecord));
		dns_msg->arcount = dns_msg->header->arcount;

		/* Parse DNS Additional Records */

		for (unsigned int ar_count = 0; ar_count < dns_msg->header->arcount; ar_count++) {
			parse_return = parse_dns_rrecord(dns_data, dns_msg->additional + ar_count, &bit_count);

			if (parse_return == PROXY_ERROR_FATAL)
				return NULL;
			else if (parse_return != PROXY_ERROR_NONE)
				goto parse_error;
		}
	}

	/* Return the parsed dns_msg{} */

	return dns_msg;

	parse_error:

	if (pd_flags & DNS_MODE_PARTIAL)
		return dns_msg;

	return NULL;
}

int domain_to_host(struct proxy_data* dns_data, unsigned long *bit_start, char** _hname)
{
	if (dns_data == NULL || dns_data->data == NULL || dns_data->size <= 0 || \
			bit_start == NULL || _hname == NULL) {
		return PROXY_ERROR_INVAL;
	}

	/* Convert domain-name to host-name */

	unsigned long _bit_start = *bit_start, cur_bit = *bit_start, \
			data_size = dns_data->size * 8;
	char* hname = (char*) calloc(1, sizeof(char));
	int add_flag = 1;

	for ( ; ; ) {
		/* Determine the label type */

		if (cur_bit + 2 > data_size)
			return PROXY_ERROR_RETRY;

		int type = bitarray_to_int(dns_data->data, cur_bit, 2);
		cur_bit = cur_bit + 2;
		if (add_flag)
			_bit_start = cur_bit;

		if (type == 0) {	// Normal label
			/* Determine the label length */

			if (cur_bit + 6 > data_size)
				return PROXY_ERROR_RETRY;

			int label_len = bitarray_to_int(dns_data->data, cur_bit, 6);
			cur_bit = cur_bit + 6;
			if (add_flag)
				_bit_start = cur_bit;

			if (label_len == 0)
				break;

			/* Append each label character to host-name */

			for (int label_count = 0; label_count < label_len; label_count++) {
				if (cur_bit + 8 > data_size)
					return PROXY_ERROR_RETRY;

				char ch[2];
				ch[1] = '\0';

				ch[0] = bitarray_to_int(dns_data->data, cur_bit, 8);
				cur_bit = cur_bit + 8;
				if (add_flag)
					_bit_start = cur_bit;

				hname = strappend(2, hname, ch);
			}

			hname = strappend(2, hname, ".");	// Append "." between labels
		}
		else if (type == 3) {	// Pointer label
			/* Determine the pointer offset */

			if (cur_bit + 14 > data_size)
				return PROXY_ERROR_RETRY;

			cur_bit = bitarray_to_int(dns_data->data, cur_bit, 14);
			if (add_flag) {
				_bit_start = _bit_start + 14;
				add_flag = 0;
			}
		}
		else
			return PROXY_ERROR_FATAL;
	}

	/* Return the host-name */

	*_hname = hname;
	*bit_start = _bit_start;

	return PROXY_ERROR_NONE;
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
