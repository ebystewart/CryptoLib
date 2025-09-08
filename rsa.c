#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"
#include "rand.h"

/* Key-pair generation steps:
  - pre-select a random number
  - apply a Fermat test (best with the base 2, as it can be optimized for speed)
  - apply a certain number of Miller-Rabin tests (depending on the length and the allowed error rate like 2pow(-100))
  
Note:
done either by test divisions by small prime numbers (up to few hundreds) or by sieving out primes up to 10,000 - 1,000,000 
considering many prime candidates of the form b+2i (b big, i up to few thousands)
*/

/* generate a random number and check if it is prime with primality test */
//static int rsa_generate_prime(rsa_keyLen_e keyLen, uint8_t *prime);

int rsa_generate_prime(rsa_keyLen_e keyLen, uint8_t *prime)
{
  uint16_t idx;
  uint32_t fMarker = 0;
  uint8_t a_chosen[2] = {2, 17}; /* preferably a smaller prime */
  /* generate a random number */
    if(prime)
        generate_random(prime, keyLen);
    printf("The generated random number of length %d is:\n", keyLen*8); 
    for(idx = 0; idx < keyLen; idx++){
      printf("%x");
    }
    printf("\n");
    /* Do primality test - Fermat's test */
    /* "p" is prime if (a*(pow(p-1) = 1 mod(p))), for all 1 <= a < p */
    /* [OR] a*pow(p-1) mod(p) = 1 */
    while(fMarker < keyLen){
      /* use binary exponentiation algorithm to find the power of p-1 */
      /* we will have to break it down into smaller exponents (by 1/2) and then do modulo arithmentic on the results */
      /* ref: https://www.youtube.com/watch?v=C7gHx2StFi8 time:4:25 */


      fMarker++;

    }
    

    /* check for false positives (Carmicheal numbers) using Miller-Rabin Test */

}

//static
bool rsa_is_equal_zero(const uint8_t *dIn, uint8_t dInLen)
{
    uint32_t idx = 0;
    for(idx = 0; idx < dInLen; idx++){
      if(dIn[idx] != 0)
          return false;
    }
    return true;
}

//static
bool rsa_is_equal_one(const uint8_t *dIn, uint8_t dInLen)
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
rsa_comparison_e rsa_is_greater_than(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2)
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
        return RSA_GREATER_THAN;
    else if (left < right)
        return RSA_LESSER_THAN;
    else 
       return RSA_EQUAL_TO;
}

//static
uint32_t rsa_decrement_by_two(const uint8_t *dIn, uint32_t dInLen, uint8_t *dOut)
{
    uint32_t dOutLen = dInLen;
    uint8_t idx = 0;
    uint8_t propagate_decrementValue = 2;
    bool iterEnd = false;
    memcpy(dOut, dIn, dInLen);
    /* Subtract the array by 2 */
    //printf("1\n");
    for(idx = dInLen; (idx > 0 || (iterEnd != true && propagate_decrementValue != 0)); idx--){
      //printf("2\n");
      if(dIn[idx-1] >= 2){
          dOut[idx-1] = dIn[idx-1] - propagate_decrementValue;
          propagate_decrementValue = 0;
          iterEnd = true;
      }
      /* handle zero crossing */
      else if(dIn[idx-1] == 1){
          iterEnd = false;
          propagate_decrementValue = 1;
          dOut[idx-1] = 0xFF;
      }
      else if (dIn[idx-1] == 0){
          iterEnd = false;
          propagate_decrementValue = 1;
          dOut[idx-1] = 0xFE;
      }
    }
    return dOutLen;
}

static uint32_t rsa_multiply_by_two(const uint8_t *dIn, uint32_t dInLen, uint8_t *dOut)
{
    uint32_t dOutLen = 0;
    uint32_t dOutLenBits = 8 * dInLen;
    uint8_t idx = 0;
    bool carry_for_lsb_prev = false;
    bool carry_for_lsb_next = false;

    /* Multiply the array by 2 
       This is equivalent to a left-shift by one position of all the array elements */
    for(idx = (dInLen - 1); idx >= 0; idx--){
        if(dIn[idx] & 0x80 == 0x80){
          carry_for_lsb_next = true;
        }
        dOut[idx] = dIn[idx] << 1;
        if(carry_for_lsb_prev)
            dOut[idx] |=  0x01;

        carry_for_lsb_prev = carry_for_lsb_next;
        dOutLenBits++;
    }
    dOutLen = dOutLenBits/8;
    return dOutLen;
}

/* ref: https://www.vedantu.com/maths/2s-complement-subtraction */
//static 
uint32_t rsa_subtract(const uint8_t *dIn1, uint32_t dInLen1, const uint8_t *dIn2, uint32_t dInLen2, uint8_t *dOut)
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
    return compLen;
}

//static 
uint32_t rsa_right_shift(const uint8_t *dIn, uint32_t dInLen, uint32_t shiftPos, uint8_t *dOut)
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
uint32_t rsa_left_shift(const uint8_t *dIn, uint32_t dInLen, uint32_t shiftPos, uint8_t *dOut)
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
void rsa_divide(const uint8_t *dividend, uint32_t dividendLen, const uint8_t *divisor, uint32_t divisorLen, uint8_t *quotient, uint32_t *quotientLen,
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
    remLen = rsa_subtract(tmpDivd, divisorLen, tmpDivr, divisorLen, tmpRem1);
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
            remLen = rsa_left_shift(tmpRem1, remLen, 1, tmpRem2);
            printf("Left-shifted remainder:\n");
            for(tmpIdx = 0 ; tmpIdx < remLen; tmpIdx++){
                printf("%x", tmpRem2[tmpIdx]);
            }
            printf("\n");
            quoLen = rsa_left_shift(tmpQuo1, quoLen, 1, tmpQuo2);
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

            if(rsa_is_greater_than(tmpRem2, remLen, tmpDivr, divisorLen) >= RSA_EQUAL_TO){
                remLen = rsa_subtract(tmpRem2, remLen, tmpDivr, divisorLen, tmpRem1);
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
void rsa_multiply(const uint8_t *multiplicant, uint32_t multiplicantLen, const uint8_t *multiplier, uint32_t multiplierLen, uint8_t *product, uint32_t *productLen)
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
    printf("\n");
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
            newLen = rsa_left_shift(temp1, len, 1, shift_holder);
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

uint8_t rsa_calculate_exponent(const uint8_t *base, uint32_t baseLen, const uint8_t *power, uint32_t powerLen, uint8_t *out)
{
    uint32_t idxx;
    uint8_t outLen = 0;
    uint8_t intPowLen = powerLen;
    uint32_t intBaseLen = baseLen * powerLen;
    bool odd_power = false;
    assert(baseLen != 0 && powerLen != 0);

    uint8_t *temp = calloc(1, powerLen);
    memcpy(temp, power, powerLen);
    printf("The power value is:\n");
    for (idxx= 0; idxx < powerLen; idxx++){
        printf("%x", temp[idxx]);
    }
    printf("\n");
    uint8_t *temp2 = calloc(1, powerLen);
    memset(temp2, 0, powerLen);

    uint8_t *temp3 = calloc(1, intBaseLen);
    /* data has to be right- aligned */
    memcpy((temp3 + intBaseLen - baseLen), base, baseLen);
    printf("The base value is:\n");
    for (idxx= 0; idxx < intBaseLen; idxx++){
        printf("%x", temp3[idxx]);
    }
    printf("\n");
    uint8_t *temp4 = calloc(1, intBaseLen);
    /* data has to be right- aligned */
    memset((temp4 + intBaseLen - baseLen), 0, intBaseLen);

    if(baseLen >= 1 && powerLen >= 1){

      if(power[powerLen - 1] & 0x01 == 1)
      {
          odd_power = true;
      }
      while(!rsa_is_equal_zero(temp2, intPowLen) && !rsa_is_equal_one(temp2, intPowLen)){
          //intBaseLen = rsa_multiply_by_two(temp3, intBaseLen, temp4);
          rsa_multiply((temp3 + intBaseLen - baseLen), baseLen, (temp3 + intBaseLen - baseLen), baseLen, temp4, &intBaseLen);
          memcpy(temp3, temp4, intBaseLen);    
          printf("The exponent value is:\n");
          for (idxx= 0; idxx < intBaseLen; idxx++){
              printf("%x", temp4[idxx]);
          }
          printf("\n");

          //intPowLen = rsa_decrement_by_two(temp, intPowLen, temp2);
          rsa_right_shift(temp, intPowLen, 1, temp2);
          memcpy(temp, temp2, intPowLen);
          printf("The decremented power value is:\n");
          for (idxx= 0; idxx < intPowLen; idxx++){
              printf("%x", temp2[idxx]);
          }
          printf("\n");
      }
      /* handle odd exponent */
      if(odd_power){
          rsa_multiply(temp3, sizeof(temp3), base, sizeof(base), temp4, &intBaseLen);
      }
      memcpy(out, temp4, intBaseLen);
    }
    outLen = intBaseLen;

    free(temp);
    free(temp2);
    free(temp3);
    free(temp4);
    return outLen;
}