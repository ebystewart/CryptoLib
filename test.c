#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "aes.h"
#include "rsa.h"

uint8_t in[16] = {0x63, 0x2F, 0xAF, 0xA2,
               0xEB, 0x93, 0xC7, 0x20,
               0x9F, 0x92, 0xAB, 0xCB,
               0xA0, 0xC0, 0x30, 0x2B};

uint8_t out[16] = {0};
uint8_t temp[16] = {0};
uint8_t temp2[16] = {0};
uint8_t round_key[16] = {0};

/* 0x54776F204F6E65204E696E652054776F */
uint8_t plain_text[16] = {0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F};
uint8_t cipher_text[16] = {0xa7, 0x9f, 0x34, 0xe3, 0xd6, 0x88, 0x74, 0x0c, 0x2e, 0x56, 0x5a, 0xae, 0x32, 0xc0, 0x8c, 0x3b};
// AES_128 output {0x29, 0xc3, 0x50, 0x5f, 0x57, 0x14, 0x20, 0xf6, 0x40, 0x22, 0x99, 0xb3, 0x1a, 0x02, 0xd7, 0x3a};
// AES_192 output {0xa7, 0x9f, 0x34, 0xe3, 0xd6, 0x88, 0x74, 0x0c, 0x2e, 0x56, 0x5a, 0xae, 0x32, 0xc0, 0x8c, 0x3b};
// AES_256 output {0x9f, 0x00, 0xa4, 0xd7, 0x13, 0x1f, 0x99, 0x5d, 0x1b, 0x60, 0x80, 0x10, 0x90, 0x3f, 0x5e, 0x82};
uint8_t key[16] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75};
/* 0x5468617473206D79204B756E67204675458616473702D69702B457E676026457 */
uint8_t key_256[32] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75,
                        0x45, 0x86, 0x16, 0x47, 0x37, 0x02, 0xD6, 0x97, 0x02, 0xB4, 0x57, 0xE6, 0x76, 0x02, 0x64, 0x57};
/* 0x5468617473206D79204B756E67204675458616473702D697 */
uint8_t key_192[24] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75,
                        0x45, 0x86, 0x16, 0x47, 0x37, 0x02, 0xD6, 0x97};
uint8_t roundKey_256[32] = {0};
uint8_t temp_256[32] = {0};
uint8_t initVal[16] = {0};
uint8_t temp_192[24] = {0};
uint8_t roundKey_192[24] = {0};

int main(int arc, char ** argv)
{
#if 0
    /* Test Case 0.1: AES 128 round keys generation */    
    int nRound = 0;
    uint8_t round8_key[16] = {0x8e, 0x51, 0xef, 0x21, 0xfa, 0xbb, 0x45, 0x22, 0xe4, 0x3d, 0x7a, 0x06, 0x56, 0x95, 0x4b, 0x6c};
    uint8_t round9_key[16] = {0};
    aes_get_round_key_128(round8_key, round9_key, 9);
#endif
#if 0
    /* Test Case 0.2: AES 192 round keys generation */   
    int nRound = 1;
    memcpy(temp_192, key_192, 24);
    while(nRound < 9){
        aes_get_round_key_192(temp_192, roundKey_192, nRound);
        for (int i = 0; i < 24; i++)
        {
            printf("%x", roundKey_192[i]);
        }
        printf("\n");
        memcpy(temp_192, roundKey_192, 24);
        nRound++;
    }
#endif
#if 0
    /* Test Case 0.3: AES 256 round keys generation */   
    int nRound = 1;
    memcpy(temp_256, key_256, 32);
    while(nRound < 8){
        aes_get_round_key_256(temp_256, roundKey_256, nRound);
        for (int i = 0; i < 32; i++)
        {
            printf("%x", roundKey_256[i]);
        }
        printf("\n");
        memcpy(temp_256, roundKey_256, 32);
        nRound++;
    }
#endif
#if 0
    //aes_create_s_box();
    //aes_mix_columns(in, out);
    //aes_transpose(in, temp);
    //aes_shift_rows(temp, out);
    memcpy(temp, key, 16);
    while(round < 10){
        aes_get_round_key(temp, out, (round + 1));
        for (int i = 0; i < 16; i++)
        {
            printf("%x", out[i]);
        }
        printf("\n");
        memcpy(temp, out, 16);
        round++;
    }
#endif
#if 0
    /* Test Case 1 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step*/
    aes_encrypt_init(AES_CBC, initVal, plain_text, out, key, AES_128);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");
    aes_encrypt_update(AES_CBC, out, temp, key, round_key, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_encrypt_end(AES_CBC, temp, temp2, round_key, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp2[i]);
    }
    printf("\n");
#endif

#if 0
 `  /* Test Case 2 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step*/
    aes_encrypt(AES_CBC, initVal, plain_text, temp, key, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");
#endif
#if 0
    aes_inverseTranspose(temp, out);
    for(int i=0; i < 16; i++){
        printf("%x", out[i]);
    }
    printf("\n");
#endif
#if 0
    /* Test Case 3 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step*/
    aes_decrypt_init(AES_CBC, initVal, cipher_text, out, key, AES_128);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");
    aes_decrypt_update(AES_CBC, out, temp, key, round_key, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_decrypt_end(AES_CBC, temp, temp2, key, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp2[i]);
    }
    printf("\n");
#endif

#if 0
    /* Test Case 5 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step*/
    aes_encrypt_init(AES_CBC, initVal, plain_text, out, key_256, AES_256);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");

    aes_encrypt_update(AES_CBC, out, temp, key_256, roundKey_256, AES_256);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_encrypt_end(AES_CBC, temp, temp2, roundKey_256, AES_256);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp2[i]);
    }
    printf("\n");
    /* Expected value: 0x9f0a4d7131f995d1b608010903f5e82 */
#endif

#if 0
    /* test Case 6 */
    aes_encrypt(AES_CBC, initVal, plain_text, temp, key_256, AES_256);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");
    /* Expected value: 0x9f0a4d7131f995d1b608010903f5e82 */
#endif
#if 0
    /* Test Case 7 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step*/
    aes_decrypt_init(AES_CBC, initVal, cipher_text, out, key_256, AES_256);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");
    aes_decrypt_update(AES_CBC, out, temp, key_256, roundKey_256, AES_256);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_decrypt_end(AES_CBC, temp, temp2, key_256, AES_256);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp2[i]);
    }
    printf("\n");
    /* Expected output: 0x54776f204f6e65204e696e652054776f */
#endif
#if 0
    /* test Case 8 */
    aes_decrypt(AES_CBC, initVal, cipher_text, temp, key_256, AES_256);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");
    /* Expected value: 0x54776f204f6e65204e696e652054776f */
#endif
#if 0
    /* Test Case 9 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step*/
    aes_encrypt_init(AES_CBC, initVal, plain_text, out, key_192, AES_192);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");

    aes_encrypt_update(AES_CBC, out, temp, key_192, roundKey_256, AES_192);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_encrypt_end(AES_CBC, temp, temp2, roundKey_256, AES_192);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp2[i]);
    }
    printf("\n");
    /* Expected value: 0xa79f34e3d68874c2e565aae32c08c3b */
#endif

#if 0
    /* test Case 10 */
    aes_encrypt(AES_CBC, initVal, plain_text, temp, key_192, AES_192);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");
    /* Expected value: 0xa79f34e3d68874c2e565aae32c08c3b */
#endif
#if 0
    /* Test Case 11 - verified against data provided by https://legacy.cryptool.org/en/cto/aes-step-by-step */
    /* input : 0xa79f34e3d688740c2e565aae32c08c3b */
    aes_decrypt_init(AES_CBC, initVal, cipher_text, out, key_192, AES_192);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");
    aes_decrypt_update(AES_CBC, out, temp, key_192, roundKey_256, AES_192);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_decrypt_end(AES_CBC, temp, temp2, key_192, AES_192);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp2[i]);
    }
    printf("\n");
    /* Expected output: 0x54776f204f6e65204e696e652054776f */
#endif
#if 0
    /* test Case 12 */
    /* input: a79f34e3d688740c2e565aae32c08c3b */
    aes_decrypt(AES_CBC, initVal, cipher_text, temp, key_192, AES_192);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");
    /* Expected value: 0x54776f204f6e65204e696e652054776f */
#endif

#if 0
    uint8_t *prime = (uint8_t *)calloc(1, RSA_1024/8);
    rsa_generate_prime(RSA_1024/8, prime);
#endif

#if 1
    uint32_t dOutLen = 0;
    uint8_t idx = 0;
    memcpy(roundKey_256, key_256, 32);
    for(idx = 0; idx < 32; idx++){
        printf("%x",roundKey_256[idx]);
    }
    printf("\n");
    while(rsa_is_equal_zero(roundKey_256) == false){
        printf("Iteration %d:\n", dOutLen);
        rsa_decrement_by_two(roundKey_256, 32, temp_256);
        for(idx = 0; idx < 32; idx++){
            printf("%x",temp_256[idx]);
        }
        dOutLen++;
        printf("\n");
        memcpy(roundKey_256, temp_256, 32);
    }
#endif
    return 0;
}