#ifndef _AEAD_H_
#define _AEAD_H_

#include <stdbool.h>
#include <stdint.h>

/* ChaCha20-Poly1305 is an authenticated encryption with associated data (AEAD) algorithm, 
   that combines the ChaCha20 stream cipher with the Poly1305 message authentication code
   Ref: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
 */

typedef enum{
    AEAD_CHACHA20_POLY1305,
    AEAD_XCHACHA20_POLY1305
}aead_suite_e;

typedef struct {
  uint8_t *plainText; 
  uint16_t plainTextLen;   /* in Bytes */
  uint16_t associatedDataLen; /* in Bytes Ex. pkt header length - TLS record header */
  uint8_t *key; 
  uint16_t keyLen; /* in bits */
  uint8_t *nonce;
  uint16_t nonceLen; /* in bits */
  uint8_t *cipherText;
  uint16_t cipherTextLen; /* in Bytes */
  uint8_t *authTag;
  uint16_t authTagLen; /* in bits */
}aead_context_t;


void aead_authenticate(aead_context_t *ctx, aead_suite_e cs);

bool aead_verify(aead_context_t *ctx, aead_suite_e cs);

#endif