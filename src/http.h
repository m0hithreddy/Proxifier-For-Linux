/* http.c declarations

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

#ifndef SRC_HTTP_H_
#define SRC_HTTP_H_

#define HTTP_CONSTANT_REQUEST_HEADERS_MAPPING " HOST 4 \
User-Agent 5 \
Accept 6 \
Accept-Encoding 7 \
Connection 8 \
Content-Type 9 \
Content-Length 10 \
Accept-Language 11 \
Referer 12 \
Upgrade-Insecure-Requests 13 \
If-Modified-Since 14 \
If-None-Match 15 \
Cache-Control 16 \
Date 17 \
Pragma 18 \
Trailer 19 \
Transfer-Encoding 20 \
Upgrade 21 \
Via 22 \
Warning 23 \
Accept-Charset 24 \
Authorization 25 \
Expect 26 \
From 27 \
If-Match 28 \
If-Match 29 \
If-Unmodified-Since 30 \
Max-Forwards 31 \
Proxy-Authorization 32 \
Range 33 \
TE 34 \
Proxy-Connection 35 "

#define HTTP_CONSTANT_RESPONSE_HEADERS_MAPPING " DATE 4 \
CONTENT-TYPE 5 \
SERVER 6 \
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

#define HTTP_CONSTANT_REQUEST_HEADERS_COUNT 35
#define HTTP_CONSTANT_RESPONSE_HEADERS_COUNT 36
#include "proxy_structures.h"
#include "proxy_socket.h"

struct http_request {
	char* method;
	char* path;
	char* version;
	char* host;
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
	char* port;
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
	struct proxy_data *body;

	// Misc Entries
	char* url;
};

struct proxy_data* create_http_request(struct http_request* s_request);

struct http_request* parse_http_request(struct proxy_data* request);

struct http_response* parse_http_response(struct proxy_data *response);

int http_method(struct proxy_client* px_client, struct proxy_data* http_request, int http_flags, struct proxy_bag* http_results);

int free_http_request(struct http_request** _s_request);

int free_http_response(struct http_response** _s_response);

#endif /* SRC_HTTP_H_ */
