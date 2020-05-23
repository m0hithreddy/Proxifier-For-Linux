/*
 * http.h
 *
 *  Created on: 18-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_HTTP_H_
#define SRC_HTTP_H_

#define HTTP_CONSTANT_REQUEST_HEADERS_MAPPING " User-Agent 6 \
Accept 7 \
Accept-Encoding 8 \
Connection 9 \
Content-Type 10 \
Content-Length 11 \
Accept-Language 12 \
Referer 13 \
Upgrade-Insecure-Requests 14 \
If-Modified-Since 15 \
If-None-Match 16 \
Cache-Control 17 \
Date 18 \
Pragma 19 \
Trailer 20 \
Transfer-Encoding 21 \
Upgrade 22 \
Via 23 \
Warning 24 \
Accept-Charset 25 \
Authorization 26 \
Expect 27 \
From 28 \
If-Match 29 \
If-Match 30 \
If-Unmodified-Since 31 \
Max-Forwards 32 \
Proxy-Authorization 33 \
Range 34 \
TE 35 \
Proxy-Connection 36 "

#define HTTP_CONSTANT_RESPONSE_HEADERS_MAPPING " DATE 4 \
CONTENT-TYPE 5 \
SERVER 6\
ACCEPT-RANGES 7 \
VARY 8 \
CONNECTION 9 \
LOCATION 10 \
CONTENT-LENGTH 11 \
KEEP-ALIVE 12 \
ACCESS-CONTROL-ALLOW-ORIGIN 13 \
LAST-MODIFIED 14 \
CONTENT-ENCODING 15 \
TRANSFER-ENCODING 16 \
ALT-SVC 17 \
CACHE-CONTROL 18 \
PRAGMA 19 \
TRAILER 20 \
UPGRADE 21 \
VIA 22 \
WARNING 23 \
AGE 24 \
ETAG 25 \
PROXY-AUTHENTICATE 26 \
RETRY-AFTER 27 \
WWW-AUTHENTICATE 28 \
ALLOW 29 \
CONTENT-LANGUAGE 30 \
CONTENT-LOCATION 31 \
CONTENT-MD5 32 \
CONTENT-RANGE 33 \
EXPIRES 34 \
EXTENSION-HEADER 35 \
Proxy-Connection 36 "

#define HTTP_MODE_SEND_REQUEST 0b001
#define HTTP_MODE_READ_HEADERS 0b010
#define HTTP_MODE_READ_RESPONSE 0b100

#include "proxy_structures.h"
#include "proxy_socket.h"

struct http_request {
	char* method;
	char* path;
	char* version;
	char* host;
	char* port;
	char* user_agent;
	char* accept;
	char* accept_encoding;
	char* connection;
	char* content_type;
	char* content_length;
	char* accept_language;
	char* referer;
	char* upgrade_insecure_requests;
	char* if_modified_since;
	char* if_none_match;
	char* cache_control;
	char* date;
	char* pragma;
	char* trailer;
	char* transfer_encoding;
	char* upgrade;
	char* via;
	char* warning;
	char* accept_charset;
	char* authorization;
	char* expect;
	char* from;
	char* if_match;
	char* if_range;
	char* if_unmodified_since;
	char* max_forwards;
	char* proxy_authorization;
	char* range;
	char* te;
	char* proxy_connection;
	char ***custom_headers; /* custom[i][0]="Header" custom[i][1]="Value" custom[end]==NULL (NULL terminating) */
	struct proxy_data* body;

	// Misc Entries
	char* url;
	char* hostip;
	char* scheme;
};

struct http_response
{
	char* version;
	char* status_code;
	char* status;
	char* date;
	char* content_type;
	char* server;
	char* accept_ranges;
	char* vary;
	char* connection;
	char* location;
	char* content_length;
	char* keep_alive;
	char* access_control_allow_orgin;
	char* last_modified;
	char* content_encoding;
	char* transfer_encoding;
	char* alt_svc;
	char* cache_control;
	char* pragma;
	char* trailer;
	char* upgrade;
	char* via;
	char* warning;
	char* age;
	char* etag;
	char* proxy_authenticate;
	char* retry_after;
	char* www_authenticate;
	char* allow;
	char* content_language;
	char* content_location;
	char* content_md5;
	char* content_range;
	char* expires;
	char* extension_header;
	char* proxy_connection;
	char ***custom_headers; /* custom[i][0]="Header" custom[i][1]="Value" custom[end]==NULL (NULL terminating) */
	char* url;
	struct proxy_data *body;
};

struct proxy_data* create_http_request(struct http_request* s_request);

struct http_response* parse_http_response(struct proxy_data *response);

int http_method(struct proxy_client* px_client, struct proxy_data* http_request, int http_flags, struct proxy_bag* http_results);

#endif /* SRC_HTTP_H_ */
