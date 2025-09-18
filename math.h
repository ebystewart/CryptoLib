#ifndef _MATH_H_
#define _MATH_H_

#include <stdint.h>

/* Rotate Right API */
uint32_t ROTR(uint32_t var, uint8_t pos);

uint32_t modulo32_add(uint32_t arg1, uint32_t arg2);

uint64_t modulo64_add(uint64_t arg1, uint64_t arg2);

void convert32_endianess(uint32_t *dIn, uint32_t *dOut, uint32_t dataLen);

#endif