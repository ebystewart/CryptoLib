#ifndef _CHACHA20_H_
#define _CHACHA20_H_

#include <stdint.h>

/* Ref: https://loup-vaillant.fr/tutorials/chacha20-design
   Ref: https://muens.io/chacha20/
*/

/* Key length is 256 bits (32 Bytes) 
   Nounce length is 96 bits (12 Bytes)
   Counter length is 32 bits (4 Bytes)
*/
int chacha20_encrypt(uint8_t *plain_text, uint32_t dataLen, uint32_t *key, uint32_t *nounce, uint32_t counter, uint8_t *cipher_text, uint32_t *dOutLen);


#endif