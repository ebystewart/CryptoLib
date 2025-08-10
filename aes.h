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
/* returns a job_id */
/* This does the first round */
int aes_encrypt_init(aes_mode_t mode, int keyLen, char *key, char *initVal, char *plain_text, char *ciper_text);

/* This API does the intermediate rounds */
/* gives the number of iterations left */
int aes_encrypt_update(int job_id, char *plain_text, char *cipher_text, int iLeft);

/* This API does the final round */
int ase_encrypt_end(int job_id, char *plain_text, char *cipher_text);

/* AES Decryption */
int aes_decrypt_init(aes_mode_t mode, int keyLen, char *key, char *initVal, char *cipher_text, char *plain_text);

int aes_decrypt_update(int job_id, char *cipher_text, char *plain_text, int iLeft);

int aes_decrypt_end(int job_id, char *cipher_text, char *plain_text);

/* Sync APIs */
int aes_encrypt(aes_mode_t mode, int keyLen, char *key, char *initVal, char *plain_text, char *ciper_text);

int aes_decrypt(aes_mode_t mode, int keyLen, char *key, char *initVal, char *cipher_text, char *plain_text);

#endif