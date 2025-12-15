#ifndef _TLS13_CRY_H_
#define _TLS13_CRY_H_
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "tls13_extensions.h"

typedef struct{
    tls13_ctxType_e     role;
    tls13_cipherSuite_e cipherSuite;
    uint8_t             *handshakeKey;
    uint16_t            handshakeKeyLen;
    uint8_t             *handshakeIV;
    uint16_t            handshakeIVLen; 
}crypt_ctx_t;

/* Static function declarations */

bool tls13_verify_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, const uint8_t *mac, const uint16_t macLen, crypt_ctx_t *ctx);

bool tls13_generate_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *mac, uint16_t macLen, crypt_ctx_t *ctx);

void tls13_encrypt(const uint8_t *plainText, const uint16_t plainTextLen, uint8_t *cipherText, crypt_ctx_t *ctx);

void tls13_decrypt(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *plainText, crypt_ctx_t *ctx);


#endif
