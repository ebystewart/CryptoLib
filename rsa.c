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
uint8_t rsa_decrement_by_two(const uint8_t *dIn, uint8_t dInLen, uint8_t *dOut)
{
    uint8_t dOutLen = 32;
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

static uint32_t rsa_multiply_by_two(const uint8_t *dIn, uint8_t dInLen, uint8_t *dOut)
{
    uint32_t dOutLen = 0;
    uint32_t dOutLenBits = 8 * dInLen;
    uint8_t idx = 0;
    bool carry_for_lsb_prev = false;
    bool carry_for_lsb_next = false;

    /* Multiply the array by 2 
       This is equivalent to a left-shift by one position ny all the array elements */
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

static void rsa_divide(const uint8_t *divident, uint8_t dividentLen, const uint8_t *divisor, uint8_t divisorLen, uint8_t *quotient, uint8_t *quotientLen,
    uint8_t * remainder, uint8_t *remainderLen)
{


}

uint8_t rsa_find_exponent(const uint8_t *base, uint8_t baseLen, const uint8_t *power, uint8_t powerLen, uint8_t *out)
{
    uint8_t outLen = 0;
    uint8_t intPowLen = powerLen;
    uint32_t intBaseLen = baseLen * 4;
    bool odd_power = false;
    assert(baseLen != 0 && powerLen != 0);

    uint8_t *temp = calloc(1, powerLen);
    memcpy(temp, power, powerLen);
    uint8_t *temp2 = calloc(1, powerLen);
    memset(temp2, 0, powerLen);
    uint8_t *temp3 = calloc(1, intBaseLen);
    memcpy(temp3, base, baseLen);
    uint8_t *temp4 = calloc(1, intBaseLen);
    memset(temp4, 0, baseLen);

    if(baseLen == 1 && powerLen == 1){

      if(power[0] & 0x01 == 1)
      {
          odd_power = true;
      }
      while(intPowLen > 0){
          intBaseLen = rsa_multiply_by_two(temp3, intBaseLen, temp4);
          memcpy(temp4, temp3, intBaseLen);
          intPowLen = rsa_decrement_by_two(temp, intPowLen, temp2);
          memcpy(temp2, temp, intPowLen);
      }
      memcpy(temp4, out, intPowLen);
    }

    free(temp);
    free(temp2);
    free(temp3);
    free(temp4);
    return outLen;
}