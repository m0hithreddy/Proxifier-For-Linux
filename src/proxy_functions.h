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
