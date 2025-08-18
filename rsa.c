#include <stdint.h>
#include <stdio.h>
#include "rsa.h"

/* Key-pair generation steps:
  - pre-select a random number
  - apply a Fermat test (best with the base 2, as it can be optimized for speed)
  - apply a certain number of Miller-Rabin tests (depending on the length and the allowed error rate like 2pow(-100))
  
Note:
done either by test divisions by small prime numbers (up to few hundreds) or by sieving out primes up to 10,000 - 1,000,000 
considering many prime candidates of the form b+2i (b big, i up to few thousands)
*/

static int rsa_generate_prime(rsa_keyLen_e keyLen, uint8_t *prime);

static int rsa_generate_prime(rsa_keyLen_e keyLen, uint8_t *prime)
{

}