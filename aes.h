#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

typedef enum{
    AES_ECB,  /* Electronic Code Book mode */
    AES_CBC,  /* Cipher Block Chaining Mode */
    AES_CFB,  /* Cipher Feedback Mode */
    AES_OFB,  /* output Feedback Mode */
    AES_GCM   /* Galois counter mode */
}aes_mode_t;

typedef enum{
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256
}aes_keylen_t;

typedef struct aes_param_{
    uint8_t *initVal;
    aes_mode_t mode;

}aes_param_t;

/* Async APIs */
/* AES Encryption */
/* returns a job_id, which is greater than 0 */
/* This does the first round */
int aes_encrypt_init(aes_mode_t mode, const uint8_t *initVal, const uint8_t *plain_text, 
                    uint8_t *cipher_text, const uint8_t *key, aes_keylen_t keyLen);

/* This API does the intermediate rounds */
/* gives the number of iterations left */
int aes_encrypt_update(aes_mode_t mode, const uint8_t *plain_text, uint8_t *cipher_text, const uint8_t *key, uint8_t *rKey, aes_keylen_t keyLen);

/* This API does the final round */
int aes_encrypt_end(aes_mode_t mode, const uint8_t *plain_text, uint8_t *cipher_text, uint8_t *round_key, aes_keylen_t keyLen);

/* AES Decryption */
int aes_decrypt_init(aes_mode_t mode, const uint8_t *initVal, const uint8_t *cipher_text, 
    uint8_t *plain_text, const uint8_t *key, aes_keylen_t keyLen);

int aes_decrypt_update(aes_mode_t mode, const uint8_t *cipher_text, uint8_t *plain_text, const uint8_t *key, uint8_t *rKey, aes_keylen_t keyLen);

int aes_decrypt_end(aes_mode_t mode, const uint8_t *cipher_text, uint8_t *plain_text, const uint8_t *round_key, aes_keylen_t keyLen);

/* Sync APIs */
int aes_encrypt(aes_mode_t mode, const uint8_t *initVal, const uint8_t *plain_text, uint8_t *cipher_text, uint8_t dataLen, const uint8_t *key, aes_keylen_t keyLen);

int aes_decrypt(aes_mode_t mode, const uint8_t *initVal, const uint8_t *cipher_text, uint8_t *plain_text, uint8_t dataLen, const uint8_t *key, aes_keylen_t keyLen);

#endif