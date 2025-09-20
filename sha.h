#ifndef SHA_H_
#define SHA_H_

#include <stdint.h>

typedef enum {
    SHA_1   = 0,
    SHA_224 = 1,
    SHA_256 = 2,
    SHA_284 = 3,
    SHA_512 = 4,
    SHA_512_224 = 5,
    SHA_512_256 = 6
}sha_type_e; 

/* SHA2 
   ref: https://en.wikipedia.org/wiki/SHA-2
*/

void sha224_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest);
void sha256_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest);
void sha384_compute_hash(uint8_t *message, uint64_t messageLen, uint8_t *digest);
void sha512_compute_hash(uint8_t *message, uint64_t messageLen, uint8_t *digest);

/* SHA3 
   Ref: 
*/

/* Common */

void sha_hash(uint8_t *message, uint32_t messageLen, sha_type_e sha_type, uint32_t *digest);

#endif