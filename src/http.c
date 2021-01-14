/*******************************************************************************
 * Copyright (C) 2020 - 2021, Mohith Reddy <dev.m0hithreddy@gmail.com>
 *
 * This file is part of Proxifier-For-Linux <https://github.com/m0hithreddy/Proxifier-For-Linux>
 *
 * Proxifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Proxifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *******************************************************************************/

#include "http.h"
#include "proxy.h"
#include "proxy_structures.h"
#include "proxy_functions.h"
#include "proxy_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct proxy_data* create_http_request(struct http_request* s_request)
{
	if (s_request == NULL)
		return NULL;

	struct proxy_bag *rqst_bag = create_proxy_bag();
	struct proxy_data rqst_data;

	/* Append HTTP method */

	rqst_data.data = (void*) strappend(2, s_request->method != NULL ? \
			s_request->method : PROXY_DEFAULT_HTTP_METHOD, " ");
	rqst_data.size = strlen((char*) rqst_data.data);

	place_proxy_data(rqst_bag, &rqst_data);
	free(rqst_data.data);

	/* Append Path */

	rqst_data.data =(void*) strappend(2, s_request->path != NULL ? \
			s_request->path : PROXY_DEFAULT_CONNECT_ADDRESS, " ");
	rqst_data.size = strlen((char*) rqst_data.data);

	place_proxy_data(rqst_bag, &rqst_data);
	free(rqst_data.data);

	/* Append HTTP version string */

	rqst_data.data =(void*) strappend(3, "HTTP/", s_request->version != NULL ? \
			s_request->version : PROXY_DEFAULT_HTTP_VERSION, "\r\n");
	rqst_data.size = strlen((char*) rqst_data.data);

	place_proxy_data(rqst_bag, &rqst_data);
	free(rqst_data.data);

	/* Append the headers pointed by s_request{} if they are set */

	struct proxy_data* hdrs_dict = create_proxy_data(strlen(HTTP_CONSTANT_REQUEST_HEADERS_MAPPING));

	memcpy(hdrs_dict->data, (void*) HTTP_CONSTANT_REQUEST_HEADERS_MAPPING, hdrs_dict->size);

	char *hdr_key = NULL, *hdr_value = NULL, *hdr_index = NULL;

	for ( ; ; ) {
		/* Seek through spaces */

		hdrs_dict = sseek(hdrs_dict, " ", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

		if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0)
			break;

		/* Read HTTP header key */

		hdr_key = NULL;
		hdrs_dict = scopy(hdrs_dict, " ", &hdr_key, LONG_MAX, PROXY_MODE_DELIMIT | \
				PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_FREE_INPUT);

		if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0 \
				|| hdr_key == NULL)
			break;

		/* Read HTTP header key's index in http_request{} */

		hdr_index = NULL;
		hdrs_dict = scopy(hdrs_dict, " ", &hdr_index, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_NULL_RESULT | PROXY_MODE_FREE_INPUT);

		if (hdr_index == NULL)
			break;

		/* Get the HTTP header value from s_request{} */

		hdr_value = *((char**) ((void*) s_request + (sizeof(char*) * (atol(hdr_index) - 1))));

		if (hdr_value == NULL)
			continue;

		/* Append the Header to Request Body */

		rqst_data.data = (void*) strappend(4, hdr_key, ": ", hdr_value, "\r\n");
		rqst_data.size = strlen((char*) rqst_data.data);

		place_proxy_data(rqst_bag, &rqst_data);
		free(rqst_data.data);
	}

	free_proxy_data(&hdrs_dict);

	/* Append custom headers */

	if (s_request->custom_headers != NULL) {
		for (long hdr_count = 0; s_request->custom_headers[hdr_count] != NULL; hdr_count++) {
			rqst_data.data = strappend(4, s_request->custom_headers[hdr_count][0], ": ", \
					s_request->custom_headers[hdr_count][1], "\r\n");
			rqst_data.size = strlen(rqst_data.data);

			place_proxy_data(rqst_bag, &rqst_data);
			free(rqst_data.data);
		}
	}

	/* Append CRLF terminating sequence */

	rqst_data.data = strdup("\r\n");
	rqst_data.size = 2;

	place_proxy_data(rqst_bag, &rqst_data);
	free(rqst_data.data);

	/* Append Body */

	if (s_request->body != NULL && s_request->body->data != NULL && s_request->body->size > 0) {
		place_proxy_data(rqst_bag, s_request->body);
	}

	/* Flatten rqst_bag{} */

	struct proxy_data* http_request_msg = flatten_proxy_bag(rqst_bag);
	free_proxy_bag(&rqst_bag);

	return http_request_msg;
}

struct http_request* parse_http_request(struct proxy_data* request)
{
	if (request == NULL || request->data == NULL || request->size <= 0)
		return NULL;

	struct http_request* s_request = (struct http_request*) calloc(1, sizeof(struct http_request));

	/* Locate CRLFCRLF sequence */

	char* term_seq = strlocate((char*) request->data, "\r\n\r\n", 0, request->size - 1);

	if (term_seq == NULL)  // No crlfcrlf => Not a valid HTTP request
		return NULL;

	/* Segregate Request Headers and Body */

	struct proxy_data* hdrs_data = create_proxy_data((long) (term_seq - (char*) request->data) + (4 * sizeof(char)));

	memcpy(hdrs_data->data, request->data, hdrs_data->size);

	if (request->size - hdrs_data->size > 0) {
		s_request->body = create_proxy_data(request->size - hdrs_data->size);
		memcpy(s_request->body->data, request->data + hdrs_data->size, s_request->body->size);
	}
	else
		s_request->body = NULL;

	/* Seek through spaces */

	hdrs_data = sseek(hdrs_data, " ", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0)
		return NULL;

	/* Extract the HTTP method */

	s_request->method = NULL;
	hdrs_data = scopy(hdrs_data, " \r\n", &(s_request->method), LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_NULL_RESULT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_request->method == NULL) {
		return NULL;
	}

	/* Extract the resource path */

	s_request->path = NULL;
	hdrs_data = scopy(hdrs_data, " \r\n", &(s_request->path), LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_NULL_RESULT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_request->path == NULL) {
		return NULL;
	}

	/* Extract the HTTP version */

	if (hdrs_data->size < 5 || strncasecmp((char*) hdrs_data->data, "HTTP/", 5) != 0) {
		return NULL;
	}

	hdrs_data->size = hdrs_data->size - 5;
	memmove(hdrs_data->data, hdrs_data->data + 5, hdrs_data->size);

	s_request->version = NULL;
	hdrs_data = scopy(hdrs_data, " \r\n", &(s_request->version), LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_NULL_RESULT | PROXY_MODE_FREE_INPUT);

	if (s_request->version == NULL)
		return NULL;

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0) {
		return s_request;
	}

	/* Request Headers Extraction */

	struct proxy_bag* cus_hdrs_bag = create_proxy_bag();

	char *hdr_key = NULL, *hdr_value = NULL, *hdr_index = NULL;

	for ( ; ; ) {
		/* Seek through spaces and \r\n */

		hdrs_data = sseek(hdrs_data, " \r\n", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

		if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0)
			break;

		/* Get request header key */

		hdr_key = NULL;
		hdrs_data = scopy(hdrs_data, " :", &hdr_key, LONG_MAX, PROXY_MODE_DELIMIT | \
				PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_FREE_INPUT);

		if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
				hdr_key == NULL)
			break;

		/* Get request header value */

		hdrs_data = scopy(hdrs_data, "\r\n", &hdr_value, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_FREE_INPUT);

		/* Locate occurrence of hdr_key in hdrs_dict */

		char* key_cmp = strappend(3, " ", hdr_key, " ");

		struct proxy_data* hdrs_dict = create_proxy_data(strlen(HTTP_CONSTANT_REQUEST_HEADERS_MAPPING));

		memcpy(hdrs_dict->data, (void*) HTTP_CONSTANT_REQUEST_HEADERS_MAPPING, hdrs_dict->size);

		char* key_pos = strcaselocate((char*) hdrs_dict->data, key_cmp, 0, hdrs_dict->size);

		/* If hdr_key found then insert in s_request{} else in s_request{}->custom_headers */

		if (key_pos != NULL) {
			/* Recompute the hdrs_dict size and seek through hdrs_dict->data */

			int seek_dist = (int) (key_pos - (char*) hdrs_dict->data) + strlen(key_cmp);

			hdrs_dict->size = hdrs_dict->size - seek_dist;
			memmove(hdrs_dict->data, hdrs_dict->data + seek_dist, hdrs_dict->size);

			/* Seek through spaces */

			hdrs_dict = sseek(hdrs_dict, " ", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

			if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0)
				continue;

			/* Get the index number of header in http_request{} */

			hdr_index = NULL;
			hdrs_dict = scopy(hdrs_dict, " ", &hdr_index, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_FREE_INPUT);

			if (hdr_index == NULL)
				continue;

			/* Fill s_request{} with the header value */

			*((char**) ((void*) s_request + (sizeof(char*) * (atol(hdr_index) - 1)))) = strdup(hdr_value);
		}
		else {
			/* Place hdr_key and hdr_value in cus_hdrs_bag */

			place_proxy_data(cus_hdrs_bag, &((struct proxy_data) {(void*) hdr_key, strlen(hdr_key) + 1}));
			place_proxy_data(cus_hdrs_bag, &((struct proxy_data) {(void*) hdr_value, strlen(hdr_value) + 1}));
		}

		free_proxy_data(&hdrs_dict);
	}

	/* Fill s_request{}->custom_headers */

	long t_hdr = (cus_hdrs_bag->n_pockets / 2) + (cus_hdrs_bag->n_pockets % 2) + 1;   // +1 for the NULL at the end.

	s_request->custom_headers = (char***) malloc(sizeof(char**) * t_hdr);

	struct proxy_pocket* hdr_pocket = cus_hdrs_bag->start;
	long hdr_count = 0;

	for( ; hdr_pocket != NULL; hdr_pocket = hdr_pocket->next, hdr_count++) {

		/* custom_headers[hdr_count][0] = hdr_key ; custom_headers[hdr_count][1] = hdr_value */

		s_request->custom_headers[hdr_count] = (char**) malloc(sizeof(char*) * 2);

		s_request->custom_headers[hdr_count][0] = (char*) memndup(hdr_pocket->data, hdr_pocket->size);

		if ((hdr_pocket = hdr_pocket->next) == NULL)
			break;

		s_request->custom_headers[hdr_count][1] = (char*) memndup(hdr_pocket->data, hdr_pocket->size);
	}

	s_request->custom_headers[hdr_count] = NULL;
	free_proxy_bag(&cus_hdrs_bag);

	return s_request;
}

struct http_response* parse_http_response(struct proxy_data *response)
{
	if (response == NULL || response->data == NULL || response->size <=0)
		return NULL;

	struct http_response *s_response = (struct http_response*) calloc(1, sizeof(struct http_response));

	/* Locate CRLFCRLF sequence */

	char* term_seq = strlocate((char*) response->data, "\r\n\r\n", 0, response->size - 1);

	if (term_seq == NULL)  // No crlfcrlf => Not a valid HTTP response
		return NULL;

	/* Segregate Response Headers and Body */

	struct proxy_data* hdrs_data = create_proxy_data((long) (term_seq - (char*) response->data) + (4 * sizeof(char)));

	memcpy(hdrs_data->data, response->data, hdrs_data->size);

	if (response->size - hdrs_data->size > 0) {
		s_response->body = create_proxy_data(response->size - hdrs_data->size);
		memcpy(s_response->body->data, response->data + hdrs_data->size, s_response->body->size);
	}
	else
		s_response->body = NULL;

	/* Seek through spaces */

	hdrs_data = sseek(hdrs_data, " ", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0)
		return NULL;

	/* Get HTTP response version */

	if (strncasecmp((char*) hdrs_data->data, "HTTP/", 5) != 0)
		return NULL;

	hdrs_data->size = hdrs_data->size - 5;
	memmove(hdrs_data->data, hdrs_data->data + 5, hdrs_data->size);

	s_response->version = NULL;
	hdrs_data = scopy(hdrs_data, " ", &s_response->version, LONG_MAX, PROXY_MODE_DELIMIT \
			| PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_response->version == NULL)
		return s_response;

	/* Get HTTP response status code */

	s_response->status_code = NULL;
	hdrs_data = scopy(hdrs_data, " ", &s_response->status_code, LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_response->status_code == NULL)
		return s_response;

	/* Get HTTP response status */

	s_response->status = NULL;
	hdrs_data = scopy(hdrs_data, " \r\n", &s_response->status, LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_NULL_RESULT | PROXY_MODE_FREE_INPUT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_response->status == NULL)
		return s_response;

	/* Response Headers Extraction */

	struct proxy_bag *cus_hdrs_bag = create_proxy_bag();

	char *hdr_key = NULL, *hdr_value = NULL, *hdr_index = NULL;

	for ( ; ; ) {
		/* Seek through spaces "\r\n" */

		hdrs_data = sseek(hdrs_data, " \r\n", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

		if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0)
			break;

		/* Get response header key */

		hdr_key = NULL;
		hdrs_data = scopy(hdrs_data, " :", &hdr_key, LONG_MAX, PROXY_MODE_DELIMIT | \
				PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_FREE_INPUT);

		if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
				hdr_key == NULL)
			break;

		/* Get response header value */

		hdrs_data = scopy(hdrs_data, "\r\n", &hdr_value, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_FREE_INPUT);

		/* Locate occurrence of hdr_key in hdrs_dict */

		char* key_cmp = strappend(3, " ", hdr_key, " ");

		struct proxy_data* hdrs_dict = create_proxy_data(strlen(HTTP_CONSTANT_RESPONSE_HEADERS_MAPPING));

		memcpy(hdrs_dict->data, (void*) HTTP_CONSTANT_RESPONSE_HEADERS_MAPPING, hdrs_dict->size);

		char* key_pos = strcaselocate((char*) hdrs_dict->data, key_cmp, 0, hdrs_dict->size);

		/* If hdr_key found then insert in s_response{} else in s_response{}->custom_headers */

		if (key_pos != NULL) {
			/* Recompute the hdrs_dict size and shift hdrs_dict->data */

			int seek_dist = (int) (key_pos - (char*) hdrs_dict->data) + strlen(key_cmp);

			hdrs_dict->size = hdrs_dict->size - seek_dist;
			memmove(hdrs_dict->data, hdrs_dict->data + seek_dist, hdrs_dict->size);

			/* Seek through spaces */

			hdrs_dict = sseek(hdrs_dict, " ", LONG_MAX, PROXY_MODE_PERMIT | PROXY_MODE_FREE_INPUT);

			if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0)
				continue;

			/* Get the index number of header in http_response{} */

			hdr_index = NULL;
			hdrs_dict = scopy(hdrs_dict, " ", &hdr_index, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_FREE_INPUT);

			if (hdr_index == NULL)
				continue;

			/* Fill s_response{} with the header value */

			*((char**) ((void*) s_response + (sizeof(char*) * (atol(hdr_index) - 1)))) = strdup(hdr_value);
		}
		else {
			/* Place hdr_key and hdr_value in cus_hdrs_bag */

			place_proxy_data(cus_hdrs_bag, &((struct proxy_data) {(void*) hdr_key, strlen(hdr_key) + 1}));
			place_proxy_data(cus_hdrs_bag, &((struct proxy_data) {(void*) hdr_value, strlen(hdr_value) + 1}));
		}

		free_proxy_data(&hdrs_dict);
	}

	/* Fill s_response{}->custom_headers */

	long t_hdr = (cus_hdrs_bag->n_pockets / 2) + (cus_hdrs_bag->n_pockets % 2) + 1;   // +1 for the NULL at the end.

	s_response->custom_headers = (char***) malloc(sizeof(char**) * t_hdr);

	struct proxy_pocket* hdr_pocket = cus_hdrs_bag->start;
	long hdr_count = 0;

	for( ; hdr_pocket != NULL; hdr_pocket = hdr_pocket->next, hdr_count++) {

		/* custom_headers[hdr_count][0] = hdr_key ; custom_headers[hdr_count][1] = hdr_value */

		s_response->custom_headers[hdr_count] = (char**) malloc(sizeof(char*) * 2);

		s_response->custom_headers[hdr_count][0] = (char*) memndup(hdr_pocket->data, hdr_pocket->size);

		if ((hdr_pocket = hdr_pocket->next) == NULL)
			break;

		s_response->custom_headers[hdr_count][1] = (char*) memndup(hdr_pocket->data, hdr_pocket->size);
	}

	s_response->custom_headers[hdr_count] = NULL;
	free_proxy_bag(&cus_hdrs_bag);

	return s_response;
}

int http_method(struct proxy_client* px_client, struct proxy_data* http_request, int http_flags, struct proxy_bag* http_results)
{
	if (px_client == NULL || px_client->sockfd < 0 || \
			((http_flags & (HTTP_MODE_READ_RESPONSE | HTTP_MODE_READ_HEADERS)) && http_results == NULL) || \
			((http_flags & HTTP_MODE_SEND_REQUEST) && (http_request == NULL || http_request->data == NULL \
					|| http_request->size <= 0))) {
		return PROXY_ERROR_INVAL;
	}

	/* HTTP Request send procedure */

	if (http_flags & HTTP_MODE_SEND_REQUEST) {
		int wr_return = proxy_socket_write(px_client, http_request, PROXY_MODE_AUTO_RETRY, NULL);

		if (wr_return != PROXY_ERROR_NONE)
			return wr_return;
	}

	/* HTTP Response Headers read procedure */

	if (http_flags & HTTP_MODE_READ_HEADERS) {
		struct proxy_bag* hdr_bag = create_proxy_bag();

		struct proxy_data hdr_data;
		hdr_data.data = malloc(1);
		hdr_data.size = 1;

		int rd_return = PROXY_ERROR_NONE, term_seq = 0b0000;
		long rd_status = 0;

		/* Read one bit at a time. FIX ME :( */

		for ( ; ; ) {
			rd_status = 0;
			rd_return = proxy_socket_read(px_client, &hdr_data, PROXY_MODE_AUTO_RETRY, &rd_status);

			if (rd_return != PROXY_ERROR_NONE && rd_return != PROXY_ERROR_RETRY && \
					rd_return != PROXY_ERROR_BUFFER_FULL)  {  // If fatal error reported by read procedure.
				return rd_return;
			}

			/* Search for HTTP headers terminating sequence "\r\n\r\n" . term_seq => 0b0000 => \n2\r2\n1\r1 */

			if (rd_status > 0) {
				place_proxy_data(hdr_bag, &hdr_data);

				if (term_seq & 0b0001) {
					if (term_seq & 0b0010) {
						if (term_seq & 0b0100) {
							if (((char*) hdr_data.data)[0] == '\n')   // If terminating sequence found.
								break;
							else
								term_seq = 0b0000;
						}
						else if (((char*) hdr_data.data)[0] == '\r')
							term_seq |= 0b0100;
						else
							term_seq = 0b0000;
					}
					else if (((char*) hdr_data.data)[0] == '\n')
						term_seq |= 0b0010;
					else
						term_seq = 0b0000;
				}
				else if (((char*) hdr_data.data)[0] == '\r')
					term_seq |= 0b0001;
			}

			if (rd_return == PROXY_ERROR_NONE)
				break;
		}

		free(hdr_data.data);

		/* Append response headers to http_results */
		struct proxy_data *px_data = flatten_proxy_bag(hdr_bag);
		place_proxy_data(http_results, &(struct proxy_data) {px_data, sizeof(struct proxy_data)});

		free_proxy_bag(&hdr_bag);
		free(px_data);
	}

	/* HTTP Response read procedure */

	if (http_flags & HTTP_MODE_READ_RESPONSE) {
		struct proxy_bag* rsp_bag = create_proxy_bag();

		struct proxy_data rsp_data;
		rsp_data.data = malloc(PROXY_MAX_TRANSACTION_SIZE);
		rsp_data.size = PROXY_MAX_TRANSACTION_SIZE;

		int rd_return = PROXY_ERROR_NONE;
		long rd_status = 0;

		/* Read till server terminates connection */

		for ( ; ; ) {
			rd_status = 0;
			rsp_data.size = PROXY_MAX_TRANSACTION_SIZE;

			rd_return = proxy_socket_read(px_client, &rsp_data, PROXY_MODE_AUTO_RETRY, &rd_status);

			if (rd_return != PROXY_ERROR_NONE || rd_return != PROXY_ERROR_RETRY || \
					rd_return != PROXY_ERROR_BUFFER_FULL) {  // Fatal error reported by read operation.
				return rd_return;
			}

			if (rd_status > 0) {
				rsp_data.size = rd_status;
				place_proxy_data(rsp_bag, &rsp_data);
			}

			if (rd_return == PROXY_ERROR_NONE)
				break;
		}

		free(rsp_data.data);

		/* Append Response data to http_results */
		struct proxy_data *px_data = flatten_proxy_bag(rsp_bag);
		place_proxy_data(http_results, &(struct proxy_data) {px_data, sizeof(struct proxy_data)});

		free_proxy_bag(&rsp_bag);
		free(px_data);
	}

	return PROXY_ERROR_NONE;
}

int free_http_request(struct http_request** _s_request) {
	if (_s_request == NULL || *_s_request == NULL) {
		return PROXY_ERROR_INVAL;
	}

	struct http_request* s_request = *_s_request;

	/* Freeing request header values */
	for (int hdr_count = 0; hdr_count < HTTP_CONSTANT_REQUEST_HEADERS_COUNT; hdr_count++) {
		free(*((char**) ((void*) s_request + hdr_count * sizeof(char*))));
	}

	/* Freeing custom header values */
	if (s_request->custom_headers != NULL) {
		int chdr_count = 0;

		for ( ; s_request->custom_headers[chdr_count] != NULL; chdr_count++) {
			free(s_request->custom_headers[chdr_count][0]);
			free(s_request->custom_headers[chdr_count][1]);

			free(s_request->custom_headers[chdr_count]);
		}

		free(s_request->custom_headers);
	}

	/* Freeing Request Body */
	free_proxy_data(&s_request->body);

	/* Freeing Misc entries */
	free(s_request->url);
	free(s_request->hostip);
	free(s_request->scheme);
	free(s_request->port);

	*_s_request = NULL;

	return PROXY_ERROR_NONE;
}

int free_http_response(struct http_response** _s_response) {
	if (_s_response == NULL || *_s_response == NULL) {
		return PROXY_ERROR_INVAL;
	}

	struct http_response* s_response = *_s_response;

	/* Freeing response header values */ 
	for (int hdr_count = 0; hdr_count < HTTP_CONSTANT_RESPONSE_HEADERS_COUNT; hdr_count++) {
		free(*((char**) ((void*) s_response + hdr_count * sizeof(char*))));
	}

	/* Freeing custom header values */
	if (s_response->custom_headers != NULL) {
		int chdr_count = 0;

		for ( ; s_response->custom_headers[chdr_count] != NULL; chdr_count++) {
			free(s_response->custom_headers[chdr_count][0]);
			free(s_response->custom_headers[chdr_count][1]);

			free(s_response->custom_headers[chdr_count]);
		}

		free(s_response->custom_headers);
	}

	/* Freeing Response Body */
	free_proxy_data(&s_response->body);

	/* Freeing Misc Entries */
	free(s_response->url); 

	*_s_response = NULL;

	return PROXY_ERROR_NONE;
}
