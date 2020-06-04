/*
 * bit.c
 *
 *  Created on: 02-Jun-2020
 *      Author: Mohith Reddy
 */

#include "bit.h"
#include "proxy.h"
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

int set_bit(void* bit_array, unsigned long bit_pos)
{
	unsigned long q = bit_pos / 8;
	unsigned long r = bit_pos % 8;

	uint8_t mask = 0b10000000;
	mask = mask >> r;

	*((uint8_t*) bit_array + q) |= mask;

	return PROXY_ERROR_NONE;
}

int clear_bit(void* bit_array, unsigned long bit_pos)
{
	unsigned long q = bit_pos / 8;
	unsigned long r = bit_pos % 8;

	uint8_t mask = 0b11111111;
	mask = mask - (0b10000000 >> r);

	*((uint8_t*) bit_array + q) &= mask;

	return PROXY_ERROR_NONE;
}

int toggle_bit(void* bit_array, unsigned long bit_pos)
{
	unsigned long q = bit_pos / 8;
	unsigned long r = bit_pos % 8;

	uint8_t mask = 0b10000000;
	mask = mask >> r;

	if (*((uint8_t*) bit_array + q) & mask)
		return clear_bit(bit_array, bit_pos);
	else
		return set_bit(bit_array, bit_pos);
}

int assign_bit(void* bit_array, unsigned long bit_pos, bit bit_val)
{
	if (bit_val == 1)
		return set_bit(bit_array, bit_pos);
	else if (bit_val == 0)
		return clear_bit(bit_array, bit_pos);

	return PROXY_ERROR_INVAL;
}

bit get_bit(void* bit_array, unsigned long bit_pos)
{
	unsigned long q = bit_pos / 8;
	unsigned long r = bit_pos % 8;

	uint8_t mask = 0b10000000;
	mask = mask >> r;

	if (*((uint8_t*) bit_array + q) & mask)
		return 1;

	return 0;
}

uint32_t bits_to_int(bit* bits, unsigned int _bit_count)
{
	uint32_t value, mask = 0b1;
	memset((void*) &value, 0, sizeof(value));

	unsigned int bit_count = _bit_count < sizeof(value) ? \
			_bit_count : sizeof(value);

	for (unsigned int cur_bit = 0; cur_bit < bit_count; cur_bit++) {
		if (bits[cur_bit] == 1) {
			value = value | (mask << (bit_count - cur_bit - 1));
		}
	}

	return value;
}

uint32_t bitarray_to_int(void* bit_array, unsigned long bit_start, unsigned int _bit_count)
{
	uint32_t value, mask = 0b1;
	memset((void*) &value, 0, sizeof(value));

	unsigned int bit_count = _bit_count < sizeof(value) ? \
			_bit_count : sizeof(value);

	for (unsigned int cur_bit = 0; cur_bit < bit_count; cur_bit++) {
		if (get_bit(bit_array, bit_start + cur_bit) == 1) {
			value = value | (mask << (bit_count - cur_bit - 1));
		}
	}

	return value;
}

int int_to_bitarray(uint32_t value, void* bit_array, unsigned long bit_start, unsigned int _bit_count)
{
	unsigned int bit_count = _bit_count < sizeof(value) ? \
			_bit_count : sizeof(value);

	uint32_t mask = 0b1 << (bit_count - 1);

	for (unsigned int cur_bit = 0; cur_bit < bit_count; cur_bit++) {
		if (value & (mask >> cur_bit))
			set_bit(bit_array, bit_start + cur_bit);
		else
			clear_bit(bit_array, bit_start + cur_bit);
	}

	return PROXY_ERROR_NONE;
}



