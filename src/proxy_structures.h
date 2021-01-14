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

#ifndef SRC_PROXY_STRUCTURES_H_
#define SRC_PROXY_STRUCTURES_H_

struct proxy_data {
	void* data;
	long size;
};

struct proxy_pocket {
	struct proxy_pocket* previous;
	void* data;
	long size;
	struct proxy_pocket* next;
};

struct proxy_bag {
	struct proxy_pocket* start;
	struct proxy_pocket* end;
	long n_pockets;
};

struct proxy_data* create_proxy_data(long px_data_size);

int free_proxy_data(struct proxy_data** px_data);

struct proxy_bag* create_proxy_bag();

int free_proxy_bag(struct proxy_bag** px_bag);

int append_proxy_pocket(struct proxy_bag* px_bag, long px_pocket_size);

int delete_proxy_pocket(struct proxy_bag* px_bag, struct proxy_pocket** _px_pocket);

int place_proxy_data(struct proxy_bag* px_bag, struct proxy_data* px_data);

struct proxy_data* flatten_proxy_bag(struct proxy_bag *px_bag);

#endif /* SRC_PROXY_STRUCTURES_H_ */
