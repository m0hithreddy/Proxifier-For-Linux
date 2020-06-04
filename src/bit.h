/*
 * bit.h
 *
 *  Created on: 02-Jun-2020
 *      Author: Mohith Reddy
 */

#ifndef SRC_BIT_H_
#define SRC_BIT_H_

#include <stdint.h>

typedef uint8_t bit;

int set_bit(void* bit_array, unsigned long bit_pos);

int clear_bit(void* bit_array, unsigned long bit_pos);

int toggle_bit(void* bit_array, unsigned long bit_pos);

int assign_bit(void* bit_array, unsigned long bit_pos, bit bit_val);

bit get_bit(void* bit_array, unsigned long bit_pos);

uint32_t bits_to_int(bit* bits, unsigned int _bit_count);

uint32_t bitarray_to_int(void* bit_array, unsigned long bit_start, unsigned int _bit_count);

int int_to_bitarray(uint32_t value, void* bit_array, unsigned long bit_start, unsigned int _bit_count);

#endif /* SRC_BIT_H_ */
