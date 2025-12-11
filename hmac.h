#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdint.h>

void hmac_hkdf_extract(const uint8_t *salt, uint32_t saltLen, const uint8_t *keyIn, uint32_t keyInLen, uint8_t *keyOut, uint32_t *keyOutLen);

void hmac_hkdf_expand_label(const uint8_t *keyIn, uint32_t keyInLen, const char *label, const uint8_t *ctx_hash, \
                            const uint32_t hashLen, uint8_t *keyOut, const uint32_t keyOutLen);

#endif