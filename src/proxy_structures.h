/*
 * proxy_structures.h
 *
 *  Created on: 17-May-2020
 *      Author: Mohith Reddy
 */

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
