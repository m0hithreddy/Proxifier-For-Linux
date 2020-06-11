/*
 * proxy_functions.c
 *
 *  Created on: 18-May-2020
 *      Author: Mohith Reddy
 */

#define _GNU_SOURCE
#include "proxy_functions.h"
#include "proxy_structures.h"
#include "proxy.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_
#include "config.h"
#endif

char* strlocate(char* haystack, char* needle, long haystack_start, long haystack_end)
{
	if (haystack == NULL || needle == NULL || haystack_start < 0 || \
			haystack_end < 0 || haystack_end < haystack_start) {
		return NULL;
	}

	/* Return the string occurrence pointer */

	return memmem(haystack + haystack_start, haystack_end - haystack_start + 1, \
			needle, strlen(needle));
}

char* strcaselocate(char* haystack, char* needle, long haystack_start, long haystack_end)
{
	if (haystack == NULL || needle == NULL || haystack_start < 0 || \
			haystack_end < 0 || haystack_end < haystack_start) {
		return NULL;
	}

	/* Create a a new sub_haystack */

	char* sub_haystack = (char*) malloc(sizeof(char) * (haystack_end - haystack_start + 2));

	memcpy(sub_haystack, haystack + haystack_start, haystack_end - haystack_start + 1);
	sub_haystack[haystack_end - haystack_start + 1] = '\0';

	/* Determine the occurrence of needle in sub_haystack */

	char* hs_needle = strcasestr(sub_haystack, needle);

	if (hs_needle == NULL)
		return NULL;

	/* haystack + relative position is the result */

	return haystack + haystack_start + \
			((long) (hs_needle) - (long) (sub_haystack));
}

struct proxy_data* sseek(struct proxy_data* px_data, char* seq_str, long max_seek, int ss_flags)
{
	if (px_data == NULL || px_data->data == NULL || \
			px_data->size <= 0 || max_seek <= 0) {	// Invalid Request
		return px_data;
	}

	/* Seek through the characters */

	char seek_buf[2]; seek_buf[1] = '\0';
	long seek_count = 0, seq_len = strlen(seq_str);

	for ( ; seek_count < px_data->size && seek_count < max_seek; seek_count += sizeof(char)) {
		seek_buf[0] = *((char*) (px_data->data + seek_count));

		if (ss_flags & PROXY_MODE_DELIMIT) {	// If requested for delimiting operation
			if (strlocate(seq_str, seek_buf, 0, seq_len) != NULL)
				break;
		}
		else {
			if (strlocate(seq_str, seek_buf, 0, seq_len) == NULL)
				break;
		}
	}

	/* Send a proxy_data{} update */

	struct proxy_data *px_update = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	px_update->data = px_data->data + seek_count;
	px_update->size = px_data->size - seek_count;

	return px_update;
}

struct proxy_data* scopy(struct proxy_data* px_data, char* seq_str, char** sc_result, long max_copy, int sc_flags)
{
	if (px_data == NULL || px_data->data == NULL || px_data->size <= 0 \
			|| max_copy <= 0 || sc_result == NULL) {	// Invalid Request
		return px_data;
	}

	/* Copy the characters into a bag*/

	struct proxy_bag *copy_bag = create_proxy_bag();
	char copy_buf[2]; copy_buf[1] = '\0';
	long copy_count = 0, seq_len = strlen(seq_str);

	for ( ; copy_count < px_data->size && copy_count < max_copy; copy_count += sizeof(char)) {
		copy_buf[0] = *((char*) (px_data->data + copy_count));

		if (sc_flags & PROXY_MODE_DELIMIT) {	// If requested for delimiting operation
			if (strlocate(seq_str, copy_buf, 0, seq_len) != NULL)
				break;
		}
		else {
			if(strlocate(seq_str, copy_buf, 0, seq_len) == NULL)
				break;
		}

		place_proxy_data(copy_bag, &((struct proxy_data) {(void*) copy_buf, sizeof(char)}));
	}

	/* Copy the results */

	if (copy_count > 0 || !(sc_flags & PROXY_MODE_NULL_RESULT)) {	/* If char copied or NULL_RESULT is not requested */
		copy_buf[0] = '\0';
		place_proxy_data(copy_bag, &((struct proxy_data) {(void*) copy_buf, sizeof(char)}));

		*sc_result = (char*) (flatten_proxy_bag(copy_bag)->data);
	}
	else
		*sc_result = NULL;

	/* Make a proxy_data{} update */

	struct proxy_data* px_update = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	px_update->data = px_data->data + copy_count;
	px_update->size = px_data->size - copy_count;

	/* If caller requested for any seeking operation */

	if (sc_flags & PROXY_MODE_SCOPY_SSEEK_DELIMIT)
		px_update = sseek(px_update, seq_str, LONG_MAX, PROXY_MODE_DELIMIT);

	if (sc_flags & PROXY_MODE_SCOPY_SSEEK_PERMIT)
		px_update = sseek(px_update, seq_str, LONG_MAX, PROXY_MODE_PERMIT);

	return px_update;
}

char* strappend(long nargs, ...)
{
	va_list ap;

	/* Compute the memory requirements for new string */

	va_start(ap, nargs);
	long t_size = 0;

	for (long arg_count = 0; arg_count < nargs; arg_count++) {
		t_size = t_size + strlen(va_arg(ap, char*));
	}
	va_end(ap);

	/* Allocate memory and prepare new string */

	char* t_str = (char*) malloc(sizeof(char) * (t_size + 1));

	if (t_str == NULL)
		return NULL;

	*t_str = '\0';

	va_start(ap, nargs);
	for (long arg_count = 0; arg_count < nargs; arg_count++) {
		strcat(t_str, va_arg(ap, char*));
	}
	va_end(ap);

	return t_str;
}

#ifndef HAVE_MEMNDUP
void* memndup(void* source, long len)
{
	if (source == NULL || len <= 0)
		return NULL;

	void* dest = malloc(len);

	/* If unsuccessful in allocating memory */

	if (dest == NULL)
		return NULL;

	memcpy(dest, source, len);

	return dest;
}
#endif
