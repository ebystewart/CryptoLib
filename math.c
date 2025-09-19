#include <stdio.h>
#include <stdbool.h>
#include "math.h"


uint32_t ROTR(uint32_t var, uint8_t pos)
{
    uint8_t idx;
    uint32_t retVal = var;
    for(idx = 0; idx < pos; idx++){
        retVal = (retVal >> 1) | ((retVal & 0x01) << 7);
    }
    return retVal;
}

uint32_t modulo32_add(uint32_t arg1, uint32_t arg2)
{
    uint32_t idx;
    uint32_t retVal = 0UL;
    bool sum;
    bool ls;
    bool rs;
    bool carry = 0;
    for (idx = 0; idx < 32; idx++)
    {
        ls = (arg1 >> idx) & 0x01;
        rs = (arg2 >> idx) & 0x01;
        sum = ls ^ rs ^ carry;
        if (ls == 1 && rs == 1 && carry == 1)
            carry = 1;
        else if ((ls == 1 || rs == 1) && carry == 1)
            carry = 1;
        else
            carry = 0;

        retVal |= ((uint32_t)sum << idx);
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
        ls = (arg1 >> idx) & 0x01;
        rs = (arg2 >> idx) & 0x01;
        sum = ls ^ rs ^ carry;
        if (ls == 1 && rs == 1 && carry == 1)
            carry = 1;
        else if ((ls == 1 || rs == 1) && carry == 1)
            carry = 1;
        else
            carry = 0;

        retVal |= ((uint64_t)sum << idx);
    }
    return retVal;
}

void convert32_endianess(uint32_t *dIn, uint32_t *dOut, uint32_t dataLen)
{
    uint8_t idx;
    uint32_t *temp = calloc(1, dataLen);
    
    for(idx = 0; idx < dataLen; idx++){

        temp[idx] = ((dIn[idx] >> 24) & 0xFF) | (((dIn[idx] >> 16) & 0xFF) << 8)| (((dIn[idx] >> 8) & 0xFF) << 16) | ((dIn[idx] & 0xFF) << 24);
        printf("in: %x, op: %x\n", dIn[idx], temp[idx]);
    }
    memcpy(dOut, temp, dataLen);
    free(temp);
}