#ifndef _POLY1305_H_
#define _POLY1305_H_

#include "stdint.h"

/* Ref: https://muens.io/poly1305/ 
   Ref: https://muens.io/poly1305/#:~:text=How%20it%20works,a%20corresponding%20MAC%20via%20Poly1305.
*/

/* Poly1305 MAC APIs */

/* This does the first round */
int poly1305_init(const uint8_t *plain_text, uint32_t dataLen, const uint8_t *key, uint8_t keyLen, uint8_t *mac);

/* This API does the intermediate rounds */
/* gives the number of iterations left */
int poly1305_update(const uint8_t *plain_text, uint32_t dataLen, const uint8_t *key, uint8_t keyLen, uint8_t *mac);

/* This API does the final round */
int poly1305_finish(const uint8_t *plain_text, uint32_t dataLen, const uint8_t *key, uint8_t keyLen, uint8_t *mac);

int poly1305_mac_generate(const uint8_t *plain_text, uint32_t dataLen, const uint8_t *key, uint8_t keyLen, uint8_t *mac);

int poly1305_mac_verify(const uint8_t *mac, const uint8_t *key, uint8_t keyLen, uint8_t *plain_text, uint32_t dataLen);

#endif