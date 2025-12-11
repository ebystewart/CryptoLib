#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdint.h>
#include <stdlib.h>

typedef enum {
    HMAC_SHA1_1    = 0x0110,
    HMAC_SHA2_224  = 0x021C,
    HMAC_SHA2_256  = 0x0220,
    HMAC_SHA2_384  = 0x0230,
    HMAC_SHA2_512  = 0x0240,
    HMAC_SHA3_224  = 0x031C,
    HMAC_SHA3_256  = 0x0320,
    HMAC_SHA3_384  = 0x0330,
    HMAC_SHA3_512  = 0x0340,
    HMAC_SHAKE_128 = 0x3310,
    HMAC_SHAKE_256 = 0x3320
}hmac_sha_e; 


void hmac_generate(const uint8_t *message, size_t msgLen, const uint8_t *key, size_t keyLen, hmac_sha_e type, uint8_t *digest, size_t *digestLen);

void hmac_hkdf_extract(const uint8_t *salt, uint32_t saltLen, const uint8_t *keyIn, uint32_t keyInLen, uint8_t *keyOut, uint32_t *keyOutLen);

void hmac_hkdf_expand_label(const uint8_t *keyIn, uint32_t keyInLen, const char *label, const uint8_t *ctx_hash, \
                            const uint32_t hashLen, uint8_t *keyOut, const uint32_t keyOutLen);

#endif