/*
 * proxy_functions.h
 *
 *  Created on: 18-May-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_PROXY_FUNCTIONS_H_
#define SRC_PROXY_FUNCTIONS_H_

#define PROXY_MODE_DELIMIT 0b00001
#define PROXY_MODE_PERMIT 0b00000
#define PROXY_MODE_NULL_RESULT 0b00010
#define PROXY_MODE_SCOPY_SSEEK_DELIMIT 0b00100
#define PROXY_MODE_SCOPY_SSEEK_PERMIT 0b01000
#define PROXY_MODE_FREE_INPUT 0b10000

#include "proxy_structures.h"

char* strlocate(char* haystack, char* needle, long haystack_start, long haystack_end);

char* strcaselocate(char* haystack, char* needle, long haystack_start, long haystack_end);

struct proxy_data* sseek(struct proxy_data* px_data, char* seq_str, long max_seek, int ss_flags);

struct proxy_data* scopy(struct proxy_data* px_data, char* seq_str, char** sc_result, long max_copy, int sc_flags);

char* strappend(long nargs, ...);

#ifndef HAVE_MEMNDUP
void* memndup(void* source, long len);
#endif

#endif /* SRC_PROXY_FUNCTIONS_H_ */
