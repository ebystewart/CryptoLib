#ifndef _MATH_H_
#define _MATH_H_

#include <stdint.h>
#include <stdbool.h>

/* Rotate Right API */
uint32_t ROTR(uint32_t var, uint8_t pos);

uint64_t ROTR64(uint64_t var, uint8_t pos);

uint32_t modulo32_add(uint32_t arg1, uint32_t arg2);

uint64_t modulo64_add(uint64_t arg1, uint64_t arg2);

void convert8_endianess(uint8_t *dIn, uint8_t *dOut, uint8_t dataLen);

void convert32_endianess(uint32_t *dIn, uint32_t *dOut, uint32_t dataLen);

void convert64_endianess(uint64_t *dIn, uint64_t *dOut, uint64_t dataLen);

void xor(uint8_t *dOut, uint8_t *dIn, uint32_t dataLen);

void xor2(uint8_t *dIn1, uint8_t *dIn2, uint32_t dLen, uint8_t *dOut);

void not(const uint8_t *dIn, uint8_t *dOut, uint32_t dataLen);

void negative_of(const uint8_t *dIn, uint8_t *dOut, uint32_t dataLen);

bool is_equal(const uint8_t *dIn1, uint32_t dIn1Len, const uint8_t *dIn2, uint32_t dIn2Len);

bool is_equal_zero(const uint8_t *dIn, uint8_t dInLen);

bool is_equal_one(const uint8_t *dIn, uint8_t dInLen);

uint32_t is_greater_than(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2);

uint32_t right_shift(const uint8_t *dIn, uint32_t dInLen, uint32_t shiftPos, uint8_t *dOut);

uint32_t left_shift(const uint8_t *dIn, uint32_t dInLen, uint32_t shiftPos, uint8_t *dOut);

void multiply(const uint8_t *multiplicant, uint32_t multiplicantLen, const uint8_t *multiplier, 
                    uint32_t multiplierLen, uint8_t *product, uint32_t *productLen);

void divide(const uint8_t *dividend, uint32_t dividendLen, const uint8_t *divisor, uint32_t divisorLen, uint8_t *quotient, uint32_t *quotientLen,
                        uint8_t * remainder, uint32_t *remainderLen);

void add(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen);

void subtract(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen);

#endif