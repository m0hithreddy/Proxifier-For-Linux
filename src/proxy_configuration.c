/*
 * proxy_configuration.c
 *
 *  Created on: 28-May-2020
 *      Author: Mohith Reddy
 */

#include "proxy_configuration.h"
#include "proxy_structures.h"
#include "proxy_functions.h"
#include "proxy.h"
#include "proxy_http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>

int get_proxy_handlers(char* config_file, struct proxy_bag* gh_results)
{
	if (config_file == NULL || gh_results == NULL)
		return PROXY_ERROR_INVAL;

	FILE* config_fp = fopen(config_file, "r");

	if (config_fp == NULL)
		return PROXY_ERROR_FATAL;

	/* Read the config_file data into proxy_bag{} then into proxy_data{} */

	struct proxy_bag* config_bag = create_proxy_bag();

	struct proxy_data* config_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));
	config_data->data = malloc(PROXY_MAX_TRANSACTION_SIZE);
	config_data->size = PROXY_MAX_TRANSACTION_SIZE;

	long rd_status = 0;

	for ( ; ; ) {
		rd_status = read(fileno(config_fp), config_data->data, PROXY_MAX_TRANSACTION_SIZE);

		if (rd_status < 0) {
			fclose(config_fp);
			return PROXY_ERROR_FATAL;
		}
		else if (rd_status == 0) {
			fclose(config_fp);
			break;
		}

		config_data->size = rd_status;
		place_proxy_data(config_bag, config_data);
	}

	config_data = flatten_proxy_bag(config_bag);

	free_proxy_bag(&config_bag);

	/* Parse the config_file data */

	char* conf_key = NULL;
	char* conf_value = NULL;
	int key_read = 0, fh_return = PROXY_ERROR_NONE;
	struct config_state* conf_state = NULL;

	for ( ; ; ) {
		/* Skip the spaces and empty lines */

		config_data = sseek(config_data, " \n", LONG_MAX, PROXY_MODE_PERMIT);

		if (config_data == NULL || config_data->data == NULL || config_data->size <= 0)
			return PROXY_ERROR_NONE;

		/* Read the Text */

		if (((char*) config_data->data)[0] == '#')	{	/* If text is starting with '#',
		 consider the whole line as comment. */
			config_data = sseek(config_data, "\n", LONG_MAX, PROXY_MODE_DELIMIT);
		}
		else {	// read conf_key or conf_value.
			if (((char*) config_data->data)[0] == '\'' || \
					((char*) config_data->data)[0] == '"') {	/* If starting with ' or " ,
					read till ' or " */

				int quote = ((char*) config_data->data)[0] == '\'' ? 1 : 0;

				config_data->data = config_data->data + 1;
				config_data->size = config_data->size - 1;

				config_data = scopy(config_data, quote ? "'" : "\"", key_read ? \
						(conf_value = NULL, &conf_value) : (conf_key = NULL, &conf_key), LONG_MAX, PROXY_MODE_DELIMIT);

				if (config_data == NULL || config_data->data == NULL || config_data->size < 1)
					return PROXY_ERROR_NONE;

				config_data->data = config_data->data + 1;
				config_data->size = config_data->size - 1;
			}
			else {
				config_data = scopy(config_data, " \n#", key_read ? (conf_value = NULL, &conf_value) : \
						(conf_key = NULL, &conf_key), LONG_MAX, PROXY_MODE_DELIMIT);
			}

			if (key_read) {
				if (conf_state == NULL) {
					conf_state = (struct config_state*) calloc(1, sizeof(struct config_state));
				}

				fh_return = fill_proxy_handler(conf_key, conf_value, conf_state);

				if (fh_return == PROXY_ERROR_NONE) {
					place_proxy_data(gh_results, &((struct proxy_data) {(void*) conf_state->px_handler, \
						sizeof(struct proxy_handler)}));
					conf_state = NULL;
				}
				else if (fh_return != PROXY_ERROR_RETRY)
					conf_state = NULL;
			}

			key_read = !key_read;
		}
	}

	return PROXY_ERROR_NONE;
}

int fill_proxy_handler(char* conf_key, char* conf_value, struct config_state* conf_state)
{
	if (conf_key == NULL || conf_value == NULL || conf_state == NULL) {
		return PROXY_ERROR_INVAL;
	}

	if (strcasecmp(conf_key, "proxy_block") == 0) {
		if (strcasecmp(conf_value, "start") == 0) {
			conf_state->start = 1;
			return PROXY_ERROR_RETRY;
		}
		else if (strcasecmp(conf_value, "end") == 0) {
			conf_state->end = 1;
			if (conf_state->start <= 0 || validate_proxy_handler(conf_state->px_handler) != PROXY_ERROR_NONE)
				return PROXY_ERROR_INVAL;

			return PROXY_ERROR_NONE;
		}
		else
			return PROXY_ERROR_FATAL;
	}

	/* Checks for conf_block starting and ending */

	if (conf_state->start <= 0)	// block did not start
		return PROXY_ERROR_INVAL;

	if (conf_state->end > 0)	// block already ended
		return PROXY_ERROR_INVAL;

	/* Initialize conf_state->px_handler{} and conf_state->px_handler->px_opt{} */

	if (conf_state->px_handler == NULL) {
		conf_state->px_handler = calloc(1, sizeof(struct proxy_handler));

		/* Default px_handler{} config_options */

		conf_state->px_handler->ptid = pthread_self();
	}

	if (conf_state->px_handler->px_opt == NULL) {
		conf_state->px_handler->px_opt = (struct proxy_options*) calloc(1, sizeof(struct proxy_options));

		/* Default px_opt{} config_options */

		conf_state->px_handler->px_opt->sigmask = PROXY_DEFAULT_SYNC_MASK;
		conf_state->px_handler->px_opt->io_timeout = PROXY_DEFAULT_IOTIMEOUT;
		conf_state->px_handler->px_opt->signo = PROXY_DEFAULT_SYNC_SIGNAL;
	}

	/* General configuration options */

	if (strcasecmp(conf_key, "proxy_type") == 0) {
		if (strcasecmp(conf_value, "HTTP_PROXY") == 0) {
			conf_state->px_handler->protocol = PROXY_PROTOCOL_HTTP;
		}
		else if (strcasecmp(conf_value, "DNS_PROXY") == 0) {
			conf_state->px_handler->protocol = PROXY_PROTOCOL_DNS;
		}
		else
			return PROXY_ERROR_FATAL;

		return PROXY_ERROR_RETRY;
	}
	else if (strcasecmp(conf_key, "proxy_server_address") == 0) {
		struct proxy_data* value_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));
		value_data->data = conf_value;
		value_data->size = strlen(conf_value);

		/* Seek the spaces and commas */

		value_data = sseek(value_data, " ,", LONG_MAX, PROXY_MODE_PERMIT);

		if (value_data == NULL || value_data->data == NULL || value_data->size <= 0)
			return PROXY_ERROR_RETRY;

		char* hostname = NULL;
		scopy(value_data, " ,", &hostname, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_NULL_RESULT);

		if (hostname == NULL)
			return PROXY_ERROR_RETRY;

		conf_state->px_handler->px_opt->px_server = strdup(hostname);

		return PROXY_ERROR_RETRY;
	}
	else if (strcasecmp(conf_key, "proxy_server_port") == 0) {
		struct proxy_data* value_data = (struct proxy_data*) calloc(1, sizeof(struct proxy_data));
		value_data->data = conf_value;
		value_data->size = strlen(conf_value);

		/* Seek the spaces and commas */

		value_data = sseek(value_data, " ,", LONG_MAX, PROXY_MODE_PERMIT);

		if (value_data == NULL || value_data->data == NULL || value_data->size <= 0)
			return PROXY_ERROR_RETRY;

		char* port = NULL;
		scopy(value_data, " ,", &port, LONG_MAX, PROXY_MODE_DELIMIT | PROXY_MODE_NULL_RESULT);

		if (port == NULL)
			return PROXY_ERROR_RETRY;

		conf_state->px_handler->px_opt->px_port = strdup(port);

		return PROXY_ERROR_RETRY;
	}
	else if (strcasecmp(conf_key, "proxy_server_username") == 0) {
		if (*conf_value == '\0')
			conf_state->px_handler->px_opt->px_username = NULL;
		else
			conf_state->px_handler->px_opt->px_username = strdup(conf_value);

		return PROXY_ERROR_RETRY;
	}
	else if (strcasecmp(conf_key, "proxy_server_password") == 0) {
		if (*conf_value == '\0')
			conf_state->px_handler->px_opt->px_password = NULL;
		else
			conf_state->px_handler->px_opt->px_password = strdup(conf_value);

		return PROXY_ERROR_RETRY;
	}
	else if (strcasecmp(conf_key, "proxy_redirection_port") == 0) {
		struct proxy_data* value_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));
		value_data->data = conf_value;
		value_data->size = strlen(conf_value);

		/* Seek through spaces and commas */

		value_data = sseek(value_data, " ,", LONG_MAX, PROXY_MODE_PERMIT);

		if (value_data == NULL || value_data->data == NULL || value_data->size <= 0)
			return PROXY_ERROR_FATAL;

		/* Loop through string to get redirection ports */

		struct proxy_bag* ports_bag = create_proxy_bag();
		char* port = NULL;

		for ( ; ; ) {
			port = NULL;
			value_data = scopy(value_data, " ,", &port, LONG_MAX, PROXY_MODE_DELIMIT | \
					PROXY_MODE_SCOPY_SSEEK_PERMIT | PROXY_MODE_NULL_RESULT);

			if (port == NULL)
				break;

			place_proxy_data(ports_bag, &((struct proxy_data) {(void*) &port, sizeof(char*)}));
		}

		conf_state->px_handler->px_opt->rd_ports = (char**) flatten_proxy_bag(ports_bag)->data;
		conf_state->px_handler->px_opt->nrd_ports = ports_bag->n_pockets;

		free_proxy_bag(&ports_bag);

		return PROXY_ERROR_RETRY;
	}

	/* Prepare compare buffer */

	int key_len = strlen(conf_key);
	char* key_buf = (char*) malloc(sizeof(char) * (key_len + 3));

	key_buf[0] = ' ';
	memcpy(key_buf + 1, conf_key, sizeof(char) * key_len);
	key_buf[key_len + 1] = ' ';
	key_buf[key_len + 2] = '\0';

	/* HTTP_PROXY specific configuration options */

	if (strcaselocate(HTTP_PROXY_CONFIGURATION_OPTIONS, key_buf, 0, \
			strlen(HTTP_PROXY_CONFIGURATION_OPTIONS)) != NULL) {
		if (fill_http_proxy_handler(conf_key, conf_value, conf_state->px_handler) != PROXY_ERROR_NONE)
			return PROXY_ERROR_FATAL;

		return PROXY_ERROR_RETRY;
	}

	return PROXY_ERROR_FATAL;
}

int validate_proxy_handler(struct proxy_handler* px_handler)
{
	if (px_handler == NULL)
		return PROXY_ERROR_INVAL;

	/* Protocol checks */

	if (px_handler->protocol == PROXY_PROTOCOL_HTTP) {
		if (validate_http_proxy_handler(px_handler) != PROXY_ERROR_NONE)
			return PROXY_ERROR_INVAL;
	}
	else
		return PROXY_ERROR_INVAL;

	/* Proxy option checks */

		/* Proxy redirection ports information checks */

	if (px_handler->px_opt->rd_ports == NULL || px_handler->px_opt->nrd_ports < 0)
		return PROXY_ERROR_INVAL;

		/* Sync mask checks */

	if (px_handler->px_opt->sigmask == NULL)
		return PROXY_ERROR_INVAL;

	return PROXY_ERROR_NONE;
}
