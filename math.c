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

//static
bool is_equal_zero(const uint8_t *dIn, uint8_t dInLen)
{
    uint32_t idx = 0;
    for(idx = 0; idx < dInLen; idx++){
      if(dIn[idx] != 0)
          return false;
    }
    return true;
}

//static
bool is_equal_one(const uint8_t *dIn, uint8_t dInLen)
{
    uint32_t idx = 0;
    if(dIn[dInLen - 1] == 1){
        for (idx = 0; idx < (dInLen -1); idx++)
        {
            if (dIn[idx] != 0)
                return false;
        }
        return true;
    }
    else{
        return false;
    }
}

/* An approximate algorithm (weighted downward scaling). Need to test its accuracy */
/* This method may work for numbers with relatively larger differences */
//static
uint32_t is_greater_than(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2)
{
    uint32_t idx = 0;
    uint64_t left = 0;
    uint64_t right = 0;
    uint32_t compLen = 0;
    if(dInLen1 >= dInLen2){
       compLen = dInLen1;
    }
    else{
        compLen = dInLen2;
    }
    /* Now we are comparing bytewise */
    /* algorithm should be improved to compare bitwise */
    for(idx = 0; idx < compLen; idx++){
        if(dIn1[idx] > dIn2[idx]){
            left |= (1 << (compLen - idx));
        }
        else if(dIn1[idx] < dIn2[idx]){
            right |= (1 << (compLen - idx));
        }
        else{
            left |= (1 << (compLen - idx));
            right |= (1 << (compLen - idx));
        }
    }
    /* final check */
    if(left > right)
        return 1;
    else if (left < right)
        return -1;
    else 
       return 0;
}

//static 
uint32_t right_shift(const uint8_t *dIn, uint32_t dInLen, uint32_t shiftPos, uint8_t *dOut)
{
    uint32_t idx;
    uint32_t subIdx;
    uint8_t carry = 0;
    uint32_t shiftPosCopy = shiftPos;

    /* calculate the output length in Bytes */
    uint32_t dOutLen = dInLen;
    uint8_t *tmp1 = calloc(1, dOutLen);
    uint8_t *tmp2 = calloc(1, dOutLen);
    memcpy(tmp1, dIn, dInLen);

    while(shiftPosCopy > 0){
        /*  */
        for (idx = dOutLen; idx > 0; idx--)
        {
            if(idx > 1){
                if ((tmp1[idx - 2] & 0x01) > 0)
                {
                    carry = 0x80U;
                }
                else{
                    carry = 0;
                }
            }
            else{
                carry = 0;
            }
            tmp2[idx-1] = (tmp1[idx-1] >> 1) | carry;
            printf("%x->%x\n", (idx-1), tmp2[idx-1]);
        }
        memcpy(tmp1, tmp2, dOutLen);
        shiftPosCopy--;
    }
    memcpy(dOut, tmp1, dOutLen);
    free(tmp1);
    free(tmp2);
    return dOutLen;
}

//static 
uint32_t left_shift(const uint8_t *dIn, uint32_t dInLen, uint32_t shiftPos, uint8_t *dOut)
{
    uint32_t idx;
    uint32_t subIdx;
    uint8_t carry = 0;
    uint32_t shiftPosCopy = shiftPos;
    uint32_t offset = (shiftPos/8);
    if ((shiftPos % 8) && ( dIn[0] > (0xFFU >> (shiftPos % 8)))){
        offset++;
    }

    /* calculate the output length in Bytes */
    uint32_t dOutLen = dInLen + offset;
    uint8_t *tmp1 = calloc(1, dOutLen);
    uint8_t *tmp2 = calloc(1, dOutLen);
    memcpy((tmp1 + offset), dIn, dInLen);

    while(shiftPosCopy > 0){
        /*  */
        for (idx = dOutLen; idx > 0; idx--)
        {
            tmp2[idx-1] = (tmp1[idx-1] << 1) | carry;

            if((tmp1[idx-1] & 0x80) > 0){
                carry = 1;
            }
            else{
                carry = 0;
            }
        }
        memcpy(tmp1, tmp2, dOutLen);
        shiftPosCopy--;
    }
    memcpy(dOut, tmp1, dOutLen);
    free(tmp1);
    free(tmp2);
    return dOutLen;
}

/* division by long division method 
   Ref: https://byjus.com/maths/binary-division/https://byjus.com/maths/binary-division/ 
   Ref: https://www.cuemath.com/numbers/binary-division/ */
//static 
void divide(const uint8_t *dividend, uint32_t dividendLen, const uint8_t *divisor, uint32_t divisorLen, uint8_t *quotient, uint32_t *quotientLen,
    uint8_t * remainder, uint32_t *remainderLen)
{
    uint32_t remLen;
    uint32_t quoLen = dividendLen;

    uint8_t *tmpQuo1 = calloc(1, dividendLen);
    uint8_t *tmpRem1 = calloc(1, dividendLen);
    uint8_t *tmpQuo2 = calloc(1, dividendLen);
    uint8_t *tmpRem2 = calloc(1, dividendLen);
    uint8_t *tmpDivd = calloc(1, dividendLen);
    memcpy(tmpDivd, dividend, dividendLen);
    uint8_t *tmpDivr = calloc(1, divisorLen);
    memcpy(tmpDivr, divisor, divisorLen);

    /* Step 1 - subtract the divisor from dividend (left aligned) */
    subtract(tmpDivd, divisorLen, tmpDivr, divisorLen, tmpRem1, &remLen);
    /* set the initial quotient - quotient has to be right aligned */
    tmpQuo1[dividendLen-1] = 0x01;
    uint32_t tmpIdx;
    printf("Initial remainder:\n");
    for(tmpIdx = 0 ; tmpIdx < remLen; tmpIdx++){
        printf("%x", tmpRem1[tmpIdx]);
    }
    printf("\n");
    printf("Initial quotient:\n");
    for(tmpIdx = 0 ; tmpIdx < quoLen; tmpIdx++){
        printf("%x", tmpQuo1[tmpIdx]);
    }
    printf("\n");

    //uint32_t nBitsYetToCover = (dividendLen - divisorLen) * 8U;
    uint32_t idx = 0;
    uint8_t subIdx = 0;

    /* Step 2 - loop and further do subtraction bitwise on the remainder */
    for(idx = divisorLen; idx < dividendLen; idx++){
        
        for(subIdx = 8; subIdx > 0; subIdx--){
            remLen = left_shift(tmpRem1, remLen, 1, tmpRem2);
            printf("Left-shifted remainder:\n");
            for(tmpIdx = 0 ; tmpIdx < remLen; tmpIdx++){
                printf("%x", tmpRem2[tmpIdx]);
            }
            printf("\n");
            quoLen = left_shift(tmpQuo1, quoLen, 1, tmpQuo2);
            printf("Left-shifted quotient with length %x:\n", quoLen);
            for(tmpIdx = 0 ; tmpIdx < quoLen; tmpIdx++){
                printf("(%x)%x", tmpIdx, tmpQuo2[tmpIdx]);
            }
            printf("\n");
            tmpRem2[remLen-1] |= (tmpDivd[idx] >> (subIdx - 1)) & 0x01U;
            printf("New remainder with %x's %x-th bit is:\n",tmpDivd[idx], (subIdx - 1));
            for(tmpIdx = 0 ; tmpIdx < remLen; tmpIdx++){
                printf("%x", tmpRem2[tmpIdx]);
            }
            printf("\n");

            if(is_greater_than(tmpRem2, remLen, tmpDivr, divisorLen) >= 0){
                subtract(tmpRem2, remLen, tmpDivr, divisorLen, tmpRem1, &remLen);
                tmpQuo2[dividendLen-1] |= 0x01U;
            }
            else{
                //memcpy(tmpRem1, tmpRem2, dividendLen);
            }
            memcpy(tmpRem1, tmpRem2, dividendLen);
            memcpy(tmpQuo1, tmpQuo2, dividendLen);
        }
        //memcpy(tmpQuo1, tmpQuo2, dividendLen);
    }
    memcpy(quotient, tmpQuo1, dividendLen);
    memcpy(remainder, tmpRem1, remLen);
    free(tmpQuo1);
    free(tmpRem1);
    free(tmpQuo2);
    free(tmpRem2);
    free(tmpDivd);
    free(tmpDivr);
    *quotientLen = quoLen;
    *remainderLen = remLen;
}

/* Ref: https://www.cuemath.com/numbers/binary-multiplication/ */
//static 
void multiply(const uint8_t *multiplicant, uint32_t multiplicantLen, const uint8_t *multiplier, uint32_t multiplierLen, uint8_t *product, uint32_t *productLen)
{
    uint32_t idx1;
    uint32_t idx2;
    uint8_t subIdx1;
    uint8_t subIdx2;
    uint32_t len = multiplicantLen + multiplierLen;
    uint32_t m1Len = multiplicantLen;
    uint32_t m2Len = multiplierLen;
    bool val1 = 0;
    bool val2 = 0;
    bool val3 = 0;
    uint8_t val4 = 0;
    uint8_t val5 = 0;
    uint32_t newLen = m1Len;

    bool carry = 0;

    uint8_t *temp1 = calloc(1, len);
    /* copy data right- aligned */
    memcpy((temp1 + multiplierLen), multiplicant, m1Len);
    int idxx;
    for (idxx= 0; idxx < len; idxx++){
        printf("%x", temp1[idxx]);
    }
    printf("\n multiplicantLen is %x and multiplierLen is %x\n",multiplicantLen, multiplierLen);
    uint8_t *shift_holder = calloc(1, len);
    uint8_t *temp3 = calloc(1, len);
    memset(temp3, 0, len);

    for (idx2 = m2Len; idx2 > 0; idx2--)
    {
        printf("%x\n",multiplier[idx2-1]);
        for (subIdx2 = 0; subIdx2 < 8; subIdx2++)
        {
            val2 = (multiplier[idx2-1] >> subIdx2) & 0x01U;
            printf("--> bitposition %x has %x\n", subIdx2, val2);
            if(val2 != 0)
            {
                for(idx1 = len; idx1 > 0; idx1--)
                {
                    printf("%x\n", temp1[idx1-1]);
                    val5 = 0x00U;
                    for(subIdx1 = 0; subIdx1 < 8; subIdx1++){
                        val1 = (temp1[idx1-1] >> subIdx1) & 0x01U;
                        val3 = (temp3[idx1-1] >> subIdx1) & 0x01U;
                        /* Do modulo addition */
                        val4 = val1 ^ val3 ^ carry;
                        printf("XOR of Val1: %x, val3: %x and carry: %x is val4 : %x\n",val1, val3, carry, val4);
                        val5 |= (val4 << subIdx1);
                         //temp3[idx1-1] = val5;

                        if((val1 == 1 || val3 == 1) && carry == 1){
                            printf("carry is set\n");
                            carry = 1;
                        }
                        else if(val1 == 1 && val3 == 1){
                            printf("carry is set\n");
                            carry = 1;
                        }
                        else{
                            carry = 0;
                        }
                    }
                    temp3[idx1-1] = val5;
                    printf("sum-->%x\n", temp3[idx1-1]);
                }
            }
            //newLen = rsa_left_shift((temp1 + (len - newLen)), newLen, 1, shift_holder);
            newLen = left_shift(temp1, len, 1, shift_holder);
            for (idxx= 0; idxx < len; idxx++){
                printf("%x", shift_holder[idxx]);
            }
            printf("\n");
            //memcpy((temp1 + (len - newLen)), shift_holder, newLen);
            memcpy(temp1, shift_holder, len);
        }
    }
    *productLen = len;
    memcpy(product, temp3, len);
    free(temp1);
    free(temp3);
    free(shift_holder);
}

void add(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen)
{
    uint32_t idx;
    uint8_t subIdx;
    bool addend;
    bool adder;
    bool value;
    bool carry = 0;
    uint32_t tLen; /* temporary length */
    uint32_t fLen; /* final length */
    uint32_t diffLen;

    if(dInLen1 > dInLen2){
        fLen = dInLen1;
        diffLen = dInLen1 - dInLen2;
    }
    else{
        fLen = dInLen2;
        diffLen = dInLen2 - dInLen1;
    }
    uint8_t *temp1 = calloc(1, fLen);
    uint8_t *temp2 = calloc(1, fLen);
    memcpy((temp1 + fLen - dInLen1), dIn1, fLen);
    memcpy((temp2 + fLen - dInLen2), dIn2, fLen);

    for(idx = fLen; idx > 0; idx--){
        for(subIdx = 0; subIdx < 8; subIdx++){
            /* carry needs to be handled */
            addend = (bool)((temp1[idx - 1] >> subIdx) & 0x01);
            adder = (bool)((temp2[idx - 1] >> subIdx) & 0x01);

            value = (addend ^ adder ^ carry);
            printf("idx: %x, addend:%x, adder: %x, carry: %x, value: %x\n", idx, addend, adder, carry, value);
            dOut[idx - 1] |= (value << subIdx);

            if(addend == 1 && adder == 1){
                carry = 1;
            }
            else if ((addend == 1 || adder == 1) && carry == 1){
                carry = 1;
            }
            else{
                carry = 0;
            }
        }
        value = 0;
    }
}

void subtract(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut, uint32_t *dOutLen)
{
    uint32_t idx;
    uint32_t compLen = 0;
    uint8_t subIdx;
    uint8_t *temp;
    uint8_t value = 0;
    bool subtrahend = 0;
    bool minuend = 0;
    bool carry = 0;
    if(dInLen1 >= dInLen2){
       compLen = dInLen1;
    }
    else{
        compLen = dInLen2;
    }
    /* compute 2's complement */
    temp = calloc(1, compLen);

    /* Assuming dIn2 as the smaller number */
    for(idx = 0; idx < (dInLen2 - 1); idx++){
      temp[idx] = ~dIn2[idx]; 
    }
    temp[dInLen2 - 1] = (~dIn2[dInLen2 - 1]) + 1;

    for(idx = compLen; idx > 0; idx--){
        for(subIdx = 0; subIdx < 8; subIdx++){
            /* carry needs to be handled */
            subtrahend = (dIn1[idx - 1] >> subIdx) & 0x01;
            minuend = (temp[idx - 1] >> subIdx) & 0x01;

            value = (subtrahend ^ minuend ^ carry);
            printf("compLen: %x, idx: %x, sup:%x, min: %x, carry: %x, value: %x\n", compLen, idx, subtrahend, minuend, carry, value);
            dOut[idx - 1] |= (value << subIdx);

            if(subtrahend == 1 && minuend == 1){
                carry = 1;
            }
            else if ((subtrahend == 1 || minuend == 1) && carry == 1){
                carry = 1;
            }
            else{
                carry = 0;
            }
        }
        value = 0;
    }
    free(temp);
    *dOutLen = compLen;    
}