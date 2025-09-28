#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "math.h"


uint32_t ROTR(uint32_t var, uint8_t pos)
{
    uint8_t idx;
    uint32_t retVal = var;
    for(idx = 0; idx < pos; idx++){
        retVal = (retVal >> 1) | ((retVal & 0x01) << 31);
    }
    return retVal;
}

uint64_t ROTR64(uint64_t var, uint8_t pos)
{
    uint8_t idx;
    uint64_t retVal = var;
    for(idx = 0; idx < pos; idx++){
        retVal = (retVal >> 1) | ((retVal & 0x01) << 63);
    }
    return retVal;
}

uint32_t modulo32_add(uint32_t arg1, uint32_t arg2)
{
    uint8_t idx;
    uint32_t retVal = 0UL;
    bool sum;
    bool ls = 0;
    bool rs = 0;
    bool carry = 0;
    for (idx = 0; idx < 32; idx++)
    {
        ls = (bool)((arg1 >> idx) & 1UL);
        rs = (bool)((arg2 >> idx) & 1UL);
        sum = ls ^ rs ^ carry;
        //printf("[idx:%u] ls is %x, rs is %x, carry is %x, sum is %x\n", idx, ls, rs, carry, sum);

        if (ls == 1 && rs == 1)
            carry = 1;
        else if ((ls == 1 || rs == 1) && carry == 1)
            carry = 1;
        else
            carry = 0;

        retVal |= ((uint32_t)sum << idx);
        //printf("%x\n", retVal);
    }
    return retVal;
}

uint64_t modulo64_add(uint64_t arg1, uint64_t arg2)
{
    uint8_t idx;
    uint64_t retVal = 0UL;
    bool sum;
    bool ls;
    bool rs;
    bool carry = 0;
    for (idx = 0; idx < 64; idx++)
    {
        ls = (bool)((arg1 >> idx) & 1UL);
        rs = (bool)((arg2 >> idx) & 1UL);
        sum = ls ^ rs ^ carry;
        if (ls == 1 && rs == 1)
            carry = 1;
        else if ((ls == 1 || rs == 1) && carry == 1)
            carry = 1;
        else
            carry = 0;

        retVal |= ((uint64_t)sum << idx);
    }
    return retVal;
}

void convert8_endianess(uint8_t *dIn, uint8_t *dOut, uint8_t dataLen)
{
    uint8_t idx;
    assert((dataLen % 4) == 0);
    uint8_t *temp = calloc(1, dataLen);
    /* dataLen should be 4 Bytes aligned */
    for(idx = 0; idx < dataLen;){

        temp[idx] = dIn[idx+3];
        temp[idx+1] = dIn[idx+2];
        temp[idx+2] = dIn[idx+1];
        temp[idx+3] = dIn[idx];
        //printf("in: %x, op: %x\n", dIn[idx], temp[idx]);
        //printf("in: %x, op: %x\n", dIn[idx+1], temp[idx+1]);
        //printf("in: %x, op: %x\n", dIn[idx+2], temp[idx+2]);
        //printf("in: %x, op: %x\n", dIn[idx+3], temp[idx+3]);
        idx += 4;
    }
    memcpy(dOut, temp, dataLen);
    free(temp);
}

void convert32_endianess(uint32_t *dIn, uint32_t *dOut, uint32_t dataLen)
{
    uint8_t idx;
    uint32_t *temp = calloc(1, dataLen);
    
    for(idx = 0; idx < dataLen/4; idx++){

        temp[idx] = (uint32_t)(((dIn[idx] >> 24) & 0xFF) | (((dIn[idx] >> 16) & 0xFF) << 8)| (((dIn[idx] >> 8) & 0xFF) << 16) | ((dIn[idx] & 0xFF) << 24));
        //printf("in: %x, op: %x\n", dIn[idx], temp[idx]);
    }
    memcpy(dOut, temp, dataLen);
    free(temp);
}

void convert64_endianess(uint64_t *dIn, uint64_t *dOut, uint64_t dataLen)
{
    uint32_t idx;
    uint64_t *temp = calloc(1, dataLen);
    
    for(idx = 0; idx < dataLen/8; idx++){

        temp[idx] = (uint64_t)(((dIn[idx] >> 56) & 0xFF) | 
                                (((dIn[idx] >> 48) & 0xFF) << 8) |
                                (((dIn[idx] >> 40) & 0xFF) << 16) | 
                                (((dIn[idx] >> 32) & 0xFF) << 24) | 
                                (((dIn[idx] >> 24) & 0xFF) << 32) | 
                                (((dIn[idx] >> 16) & 0xFF) << 40)| 
                                (((dIn[idx] >> 8) & 0xFF) << 48) | 
                                ((dIn[idx] & 0xFF) << 56));
        //printf("in: %x, op: %x\n", dIn[idx], temp[idx]);
    }
    memcpy(dOut, temp, dataLen);
    free(temp);
}

void xor(uint8_t *dOut, uint8_t *dIn, uint32_t dataLen)
{
    uint32_t idx;
    for (idx = 0; idx < dataLen; idx++){

        dOut[idx] ^= dIn[idx];
    }
}

void not(const uint8_t *dIn, uint8_t *dOut, uint32_t dataLen)
{
    uint32_t idx;
    for (idx = 0; idx < dataLen; idx++){

        dOut[idx] = ~dIn[idx];
    } 
}

bool is_equal(const uint8_t *dIn1, uint32_t dIn1Len, const uint8_t *dIn2, uint32_t dIn2Len)
{
    bool retVal = true;
    uint32_t idx;
    uint32_t dataLen;

    if(dIn1Len == dIn2Len)
    {
        dataLen = dIn1Len;
    }
    else{
        return false;
    }
    
    for (idx = dataLen; idx > 0; idx--)
    {
        if(dIn1[idx-1] != dIn2[idx-1])
        {
            retVal = false;
            return retVal;
        }
    }
    return retVal;
}

void multiply(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen)
{

}

void divide(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen)
{

}

void add(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen)
{

}

void subtract(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen)
{
    
}