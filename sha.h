#ifndef SHA_H_
#define SHA_H_

#include <stdint.h>

typedef enum {
   //SHA_1   = 16,
   SHA_224 = 28,
   SHA_256 = 32,
   SHA_384 = 48,
   SHA_512 = 64,
   SHA_512_224 = 0x401C,
   SHA_512_256 = 0x4020
}sha2_type_e; 

typedef enum {
   SHA3_224   = 28,
   SHA3_256   = 32,
   SHA3_384   = 48,
   SHA3_512   = 64,
   SHAKE_128  = 0x3310,
   SHAKE_256  = 0x3320
}sha3_type_e; 

/* SHA2 
   ref: https://en.wikipedia.org/wiki/SHA-2
*/

void sha224_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest);
void sha256_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest);
void sha384_compute_hash(uint8_t *message, uint64_t messageLen, uint8_t *digest);
void sha512_compute_hash(uint8_t *message, uint64_t messageLen, uint8_t *digest);

void sha512t_compute_hash(uint8_t *message, uint64_t messageLen, sha2_type_e type, uint8_t *digest);

void sha2_compute_hash(uint8_t *message, uint64_t messageLen, sha2_type_e sha_type, uint8_t *digest);

/* SHA3 
   Ref: https://en.wikipedia.org/wiki/SHA-3
   Ref: https://chemejon.wordpress.com/2021/12/06/sha-3-explained-in-plain-english/
   Ref: https://ijettjournal.org/assets/Volume-69/Issue-6/IJETT-V69I6P210.pdf
   Ref: https://recentscientific.com/sites/default/files/3617.pdf
*/

void sha3_compute_hash(uint8_t *message, uint64_t messageLen, sha3_type_e sha_type, uint8_t *digest);

#endif