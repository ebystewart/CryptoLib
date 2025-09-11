#ifndef SHA_H_
#define SHA_H_

#include <stdint.h>

typedef enum {
    SHA_1   = 0,
    SHA_256 = 1,
    SHA_512 = 3
}sha_type_e; 

void sha_compute_hash(uint8_t *message, uint32_t messageLen, sha_type_e sha_type, uint32_t *digest);

#endif