/*
 * http.c
 *
 *  Created on: 18-May-2020
 *      Author: Mohith Reddy
 */

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

	/* Append Path */

	rqst_data.data =(void*) strappend(2, s_request->path != NULL ? \
			s_request->path : PROXY_DEFAULT_CONNECT_ADDRESS, " ");
	rqst_data.size = strlen((char*) rqst_data.data);

	place_proxy_data(rqst_bag, &rqst_data);

	/* Append HTTP version string */

	rqst_data.data =(void*) strappend(3, "HTTP/", s_request->version != NULL ? \
			s_request->version : PROXY_DEFAULT_HTTP_VERSION, "\r\n");
	rqst_data.size = strlen((char*) rqst_data.data);

	place_proxy_data(rqst_bag, &rqst_data);

	/* Append Host header (requires special handling) */

	if (s_request->host != NULL) {
		if (s_request->port == NULL)
			rqst_data.data = strappend(3, "Host: ", s_request->host, "\r\n");
		else
			rqst_data.data = strappend(5, "Host: ", s_request->host, ":", \
					s_request->port, "\r\n");

		rqst_data.size = strlen((char*) rqst_data.data);

		place_proxy_data(rqst_bag, &rqst_data);
	}

	/* Append the headers pointed by s_request{} if they are set */

	struct proxy_data* hdrs_dict = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	hdrs_dict->data = HTTP_CONSTANT_REQUEST_HEADERS_MAPPING;
	hdrs_dict->size = strlen(hdrs_dict->data);

	char *hdr_key = NULL, *hdr_value = NULL, *hdr_index = NULL;

	for ( ; ; ) {
		/* Seek through spaces */

		hdrs_dict = sseek(hdrs_dict, " ", LONG_MAX, PROXY_MODE_PERMIT);

		if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0)
			break;

		/* Read HTTP header key */

		hdr_key = NULL;
		hdrs_dict = scopy(hdrs_dict, " ", &hdr_key, LONG_MAX, PROXY_MODE_DELIMIT | \
				PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT);

		if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0 \
				|| hdr_key == NULL)
			break;

		/* Read HTTP header key's index in http_request{} */

		hdr_index = NULL;
		hdrs_dict = scopy(hdrs_dict, " ", &hdr_index, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_NULL_RESULT);

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
	}

	/* Append custom headers */

	if (s_request->custom_headers != NULL) {
		for (long hdr_count = 0; s_request->custom_headers[hdr_count] != NULL; hdr_count++) {
			rqst_data.data = strappend(4, s_request->custom_headers[hdr_count][0], ": ", \
					s_request->custom_headers[hdr_count][1], "\r\n");
			rqst_data.size = strlen(rqst_data.data);

			place_proxy_data(rqst_bag, &rqst_data);
		}
	}

	/* Append CRLF terminating sequence */

	rqst_data.data = "\r\n";
	rqst_data.size = 2;

	place_proxy_data(rqst_bag, &rqst_data);

	/* Append Body */

	if (s_request->body != NULL && s_request->body->data != NULL && s_request->body->size > 0) {
		place_proxy_data(rqst_bag, s_request->body);
	}

	/* Flatten rqst_bag{} */

	struct proxy_data* http_request_msg = flatten_proxy_bag(rqst_bag);
	free_proxy_bag(&rqst_bag);

	return http_request_msg;
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

	struct proxy_data* hdrs_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	hdrs_data->data = response->data;
	hdrs_data->size = (long) (term_seq - (char*) response->data) + (4 * sizeof(char));

	if (response->size - hdrs_data->size > 0) {
		s_response->body = create_proxy_data(response->size - hdrs_data->size);
		memcpy(s_response->body->data, response->data + hdrs_data->size, s_response->body->size);
	}
	else
		s_response->body = NULL;

	/* Seek through spaces */

	hdrs_data = sseek(hdrs_data, " ", LONG_MAX, PROXY_MODE_PERMIT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0)
		return NULL;

	/* Get HTTP response version */

	if (strncasecmp((char*) hdrs_data->data, "HTTP/", 5) != 0)
		return NULL;

	hdrs_data->data = hdrs_data->data + (sizeof(char) * 5);
	hdrs_data->size = hdrs_data->size - (sizeof(char) * 5);

	s_response->version = NULL;
	hdrs_data = scopy(hdrs_data, " ", &s_response->version, LONG_MAX, PROXY_MODE_DELIMIT \
			| PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_response->version == NULL)
		return s_response;

	/* Get HTTP response status code */

	s_response->status_code = NULL;
	hdrs_data = scopy(hdrs_data, " ", &s_response->status_code, LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_response->status_code == NULL)
		return s_response;

	/* Get HTTP response status */

	s_response->status = NULL;
	hdrs_data = scopy(hdrs_data, " \r\n", &s_response->status, LONG_MAX, PROXY_MODE_DELIMIT | \
			PROXY_MODE_NULL_RESULT);

	if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
			s_response->status == NULL)
		return s_response;

	/* Response Headers Extraction */

	struct proxy_bag *cus_hdrs_bag = create_proxy_bag();

	char *hdr_key = NULL, *hdr_value = NULL, *hdr_index = NULL;

	for ( ; ; ) {
		/* Seek through spaces "\r\n" */

		hdrs_data = sseek(hdrs_data, " \r\n", LONG_MAX, PROXY_MODE_PERMIT);

		if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0)
			break;

		/* Get response header key */

		hdr_key = NULL;
		hdrs_data = scopy(hdrs_data, " :", &hdr_key, LONG_MAX, PROXY_MODE_DELIMIT | \
				PROXY_MODE_NULL_RESULT | PROXY_MODE_SCOPY_SSEEK_PERMIT);

		if (hdrs_data == NULL || hdrs_data->data == NULL || hdrs_data->size <= 0 || \
				hdr_key == NULL)
			break;

		/* Get response header value */

		hdrs_data = scopy(hdrs_data, "\r\n", &hdr_value, LONG_MAX, PROXY_MODE_DELIMIT);

		/* Locate occurrence of hdr_key in hdrs_dict */

		char* key_cmp = (char*) malloc(sizeof(char) * (strlen(hdr_key) + 3));

		key_cmp[0] = ' ';
		memcpy(key_cmp + 1, hdr_key, strlen(hdr_key));
		key_cmp[strlen(hdr_key) + 1] = ' ';
		key_cmp[strlen(hdr_key) + 2] = '\0';

		struct proxy_data* hdrs_dict = (struct proxy_data*) malloc(sizeof(struct proxy_data));

		hdrs_dict->data = HTTP_CONSTANT_RESPONSE_HEADERS_MAPPING;
		hdrs_dict->size = sizeof(char) * strlen((char*) hdrs_dict->data);

		hdrs_dict->data = (void*) strcaselocate((char*) hdrs_dict->data, key_cmp, 0, hdrs_dict->size);

		/* If hdr_key found then insert in s_response{} else in s_response{}->custom_headers */

		if (hdrs_dict->data != NULL) {
			hdrs_dict->data = hdrs_dict->data + sizeof(char) * strlen(key_cmp);

			/* Seek through spaces */

			hdrs_dict = sseek(hdrs_dict, " ", LONG_MAX, PROXY_MODE_PERMIT);

			if (hdrs_dict == NULL || hdrs_dict->data == NULL || hdrs_dict->size <= 0)
				continue;

			/* Get the index number of header in http_response{} */

			hdr_index = NULL;
			scopy(hdrs_dict, " ", &hdr_index, LONG_MAX, PROXY_MODE_DELIMIT);

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

		/* Append response headers to http_results */

		hdr_data.data = (void*) flatten_proxy_bag(hdr_bag);
		hdr_data.size = sizeof(struct proxy_data);

		place_proxy_data(http_results, &hdr_data);
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

		/* Append Response data to http_results */

		rsp_data.data = (void*) flatten_proxy_bag(rsp_bag);
		rsp_data.size = sizeof(struct proxy_data);

		place_proxy_data(http_results, &rsp_data);
	}

	return PROXY_ERROR_NONE;
}
