/*
 * proxy_structures.c
 *
 *  Created on: 17-May-2020
 *      Author: Mohith Reddy
 */

#include "proxy_structures.h"
#include "proxy.h"
#include <stdlib.h>
#include <string.h>

struct proxy_data* create_proxy_data(long px_data_size)
{
	if (px_data_size <= 0)
		return NULL;

	/* Create a new proxy_data{} */

	struct proxy_data* px_data = (struct proxy_data*) malloc(sizeof(struct proxy_data));

	if (px_data == NULL)
		return NULL;

	/* Allocate memory for px_data{}->data */

	px_data->data = malloc(px_data_size);

	if (px_data->data == NULL) {
		free(px_data);
		return NULL;
	}

	px_data->size = px_data_size;

	/* Return the px_data{} */

	return px_data;
}

int free_proxy_data(struct proxy_data** px_data)
{
	if (px_data == NULL || *px_data == NULL)
		return PROXY_ERROR_INVAL;

	/* Free px_data{}->data */

	free((*px_data)->data);

	/* Free px_data{} */

	free(*px_data);
	*px_data = NULL;

	return PROXY_ERROR_NONE;
}

struct proxy_bag* create_proxy_bag()
{
	struct proxy_bag *px_bag = (struct proxy_bag*) malloc(sizeof(struct proxy_bag));

	if (px_bag == NULL)
		return NULL;

	/* Initialize px_bag{} */

	px_bag->start = NULL;
	px_bag->end = NULL;
	px_bag->n_pockets = 0;

	/* Return the px_bag{} */

	return px_bag;
}

int free_proxy_bag(struct proxy_bag** px_bag)
{
	if (px_bag == NULL || *px_bag == NULL)
		return PROXY_ERROR_INVAL;

	struct proxy_pocket *at = NULL, *prev = NULL;

	/* Iterate and free the proxy_pocket{} */

	for (at = (*px_bag)->end; at != NULL; at = prev) {
		prev = at->previous;
		free(at->data);
		free(at);
	}

	/* Free px_bag{} */

	free(*px_bag);
	*px_bag = NULL;

	return PROXY_ERROR_NONE;
}

int append_proxy_pocket(struct proxy_bag* px_bag, long px_pocket_size)
{
	if (px_bag == NULL)
		return PROXY_ERROR_INVAL;

	/* Create a new proxy_pocket{} */

	struct proxy_pocket *px_pocket = (struct proxy_pocket*) malloc(sizeof(struct proxy_pocket));

	if (px_pocket == NULL)
		return PROXY_ERROR_FATAL;

	/* Allocate data for px_pocket{}->data */

	px_pocket->data = px_pocket_size > 0 ? malloc(px_pocket_size) : NULL;

	if (px_pocket->data == NULL && px_pocket_size > 0) {
		free(px_pocket);
		return PROXY_ERROR_FATAL;
	}

	px_pocket->size = px_pocket_size > 0 ? px_pocket_size : 0;

	/* Append px_pocket{} to px_bag{} */

	if (px_bag->n_pockets == 0) {	// If px_bag{} is empty
		px_pocket->previous = NULL;
		px_pocket->next = NULL;

		px_bag->start = px_pocket;
		px_bag->end = px_pocket;
		px_bag->n_pockets = 1;
	}
	else {
		px_pocket->previous = px_bag->end;
		px_pocket->next = NULL;

		px_bag->end->next = px_pocket;
		px_bag->end = px_pocket;
		px_bag->n_pockets = px_bag->n_pockets + 1;
	}

	return PROXY_ERROR_NONE;
}

int delete_proxy_pocket(struct proxy_bag* px_bag, struct proxy_pocket** _px_pocket)
{
	if (px_bag == NULL || _px_pocket == NULL || *_px_pocket == NULL)
		return PROXY_ERROR_INVAL;

	struct proxy_pocket* px_pocket = *_px_pocket;

	/* Update the px_bag{} depending on the position of px_pocket{} */

	if (px_pocket->previous == NULL && \
			px_pocket->next == NULL) {	// px_pocket{} == px_bag{}->start == px_bag{}->end
		px_bag->start = NULL;
		px_bag->end = NULL;
	}
	else if (px_pocket->previous == NULL) {	// px_pocket{} == px_bag{}->start
		px_bag->start = px_pocket->next;
		px_pocket->next->previous = NULL;
	}
	else if (px_pocket->next == NULL) {	// px_pocket{} == px_bag{}->end
		px_bag->end = px_pocket->previous;
		px_pocket->previous->next = NULL;
	}
	else {	// px_pocket{} != px_bag{}->start != px_bag{}->end
		px_pocket->previous->next = px_pocket->next;
		px_pocket->next->previous = px_pocket->previous;
	}

	px_bag->n_pockets = px_bag->n_pockets - 1;

	/* Free px_pocket{} */

	free(px_pocket->data);
	free(px_pocket);

	*_px_pocket = NULL;

	return PROXY_ERROR_NONE;
}

int place_proxy_data(struct proxy_bag* px_bag, struct proxy_data* px_data)
{
	if (px_bag == NULL || px_data == NULL)
		return PROXY_ERROR_INVAL;

	/* Append a proxy_pocket{} */

	int ap_status = append_proxy_pocket(px_bag, (px_data->data == NULL || px_data->size <= 0) \
			? 0 : px_data->size);

	if (ap_status != PROXY_ERROR_NONE)
		return ap_status;

	/* Copy px_data{}->data to newly created proxy_pocket{}->data */

	if (px_data->data != NULL && px_data->size > 0)
		memcpy(px_bag->end->data, px_data->data, px_data->size);

	return PROXY_ERROR_NONE;
}

struct proxy_data* flatten_proxy_bag(struct proxy_bag *px_bag)
{
	struct proxy_data* px_data = (struct proxy_data*) calloc(1, sizeof(struct proxy_data));

	if (px_bag == NULL)
		return px_data;

	/* Compute the memory requirements of new px_data{} */

	long t_size = 0;

	for (struct proxy_pocket* px_pocket = px_bag->start; px_pocket != NULL; \
	px_pocket = px_pocket->next) {
		t_size = t_size + px_pocket->size;
	}

	if (t_size <= 0)
		return px_data;

	/* Copy the data in px_bag{} to px_data{}->data */

	px_data->data = malloc(t_size);

	if (px_data->data == NULL)
		return px_data;

	for (struct proxy_pocket* px_pocket = px_bag->start; px_pocket != NULL; \
	px_pocket = px_pocket->next) {

		if (px_pocket->data != NULL && px_pocket->size > 0) {
			memcpy(px_data->data + px_data->size, px_pocket->data, px_pocket->size);
			px_data->size = px_data->size + px_pocket->size;
		}
	}

	return px_data;
}
