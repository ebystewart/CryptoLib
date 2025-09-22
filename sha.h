#ifndef SHA_H_
#define SHA_H_

#include <stdint.h>

typedef enum {
    SHA_1   = 0,
    SHA_224 = 1,
    SHA_256 = 2,
    SHA_284 = 3,
    SHA_512 = 4,
    SHA_384 = 5,
    SHA_512_224 = 6,
    SHA_512_256 = 7
}sha2_type_e; 

typedef enum {
   SHA3_224   = 0,
   SHA3_256,
   SHA3_384,
   SHA3_512,
   SHAKE_128,
   SHAKE_256
}sha3_type_e; 

/* SHA2 
   ref: https://en.wikipedia.org/wiki/SHA-2
*/

void sha224_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest);
void sha256_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest);
void sha384_compute_hash(uint8_t *message, uint64_t messageLen, uint8_t *digest);
void sha512_compute_hash(uint8_t *message, uint64_t messageLen, uint8_t *digest);

void sha512t_compute_hash(uint8_t *message, uint64_t messageLen, sha2_type_e type, uint8_t *digest);

/* SHA3 
   Ref: https://en.wikipedia.org/wiki/SHA-3
*/

/* Common */

void sha3_compute_hash(uint8_t *message, uint64_t messageLen, sha3_type_e sha_type, uint8_t *digest);

#endif