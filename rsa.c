#include <stdint.h>
#include <stdio.h>
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
  uint8_t a_chosen; /* preferably a smaller prime */
  /* generate a random number */
    if(prime)
        generate_random(prime, keyLen);
    printf("The generated random number of length %d is:\n", keyLen*8); 
    for(idx = 0; idx < keyLen; idx++){
      printf("%x");
    }
    printf("\n");
    /* Do primality test - Fermat's test */
    /* "p" is prime if (a*pow(p) - a) is a multiple of p, for all 1 <= a < p*/
    
}