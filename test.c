#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "aes.h"
#include "rsa.h"
#include "sha.h"
#include "math.h"
#include "tls13.h"

#if 0
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
#endif

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

#if 0
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

#if 0
    uint8_t dIn1[32] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    rsa_comparison_e result;
    result = rsa_is_greater_than(dIn1, 32, dIn2, 32);
    printf("The result of comparison is %d\n", result);    
#endif

#if 0
    uint8_t idx;
    uint8_t dOut[33];
    uint8_t dIn1[32] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn1[4] = {0xFF, 0xFF, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn2[4] = {0xFF, 0xFF, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t outLen;
    outLen = rsa_subtract(dIn1, sizeof(dIn1), dIn2, sizeof(dIn2), dOut);
    for (idx = 0; idx < outLen; idx++)
    {
        printf("%x", dOut[idx]);
    }
    printf("\n");
#endif

#if 0
    uint8_t idx;
    uint8_t dOut[32];
    uint8_t dIn1[32] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn1[4] = {0xFF, 0xFF, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn2[4] = {0xFF, 0xFF, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t outLen;
    outLen = rsa_right_shift(dIn1, sizeof(dIn1), 4, dOut);
    for (idx = 0; idx < outLen; idx++)
    {
        printf("%x", dOut[idx]);
    }
    printf("\n");
#endif

#if 0 //untested -> in-progress->tested->output verified only for smaller arrays
    uint8_t idx;

    /* Data Set : 1 
       Expected Product: 0x 
       status: under test */
    //
    uint8_t dOut[65];
    uint8_t dIn1[32] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //
    
    /* Data Set : 2
       Expected Product: 0x14B66DC1DF4D840
       status: success */
    //uint8_t dOut[9];
    //uint8_t dIn1[4] = {0x12, 0x34, 0x56, 0x78};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn2[4] = {0x12, 0x34, 0x56, 0x78};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /* Data Set : 3 
       Expected Product: 0x 
       status: under test */
    //uint8_t dOut[15];   
    //uint8_t dIn1[10] = {0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn2[4] = {0x12, 0x34, 0x56, 0x78};// 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    uint8_t outLen;
    rsa_multiply(dIn1, sizeof(dIn1), dIn2, sizeof(dIn2), dOut, &outLen);
    for (idx = 0; idx < outLen; idx++)
    {
        printf("%x", dOut[idx]);
    }
    printf("\n");
#endif

#if 0 //untested -> in-progress
    uint8_t idx;
    uint8_t quo[10] = {0};
    uint8_t rem[10] = {0};
    uint32_t quoLen = 0;
    uint32_t remLen = 0;

    /* Data Set : 1 
       Expected Quotient: 0x 
       Expected Remainder: 0x 
       status: under test */
    /*uint8_t dIn1[32] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};*/
    /* Data Set : 2 
       Expected Quotient: 0x100 
       Expected Remainder: 0x19A 
       Status: Successful */
    //uint8_t dIn1[10] = {0x12, 0x34, 0x56, 0x78, 0x9A};
    //uint8_t dIn2[4] = {0x12, 0x34, 0x56, 0x77};

    /* Data Set : 3
       Expected Quotient: 1000000169000 
       Expected Remainder: 0x010D10FB57B6CF27 
       status : under test & debug */
    uint8_t dIn1[10] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34};
    //0b00010010001101000101011001111000100110101011110011011110111100000001001000110100
    uint8_t dIn2[4] = {0x12, 0x34, 0x56, 0x77};
    //0b00010010001101000101011001110111
    /* Ref: https://www.rapidtables.com/calc/math/binary-calculator.html?num1=00010010001101000101011001111000100110101011110011011110111100000001001000110100&op=3&num2=00010010001101000101011001110111*/

    /* Data Set : 4
       Expected Quotient: 0x 
       Expected Remainder: 0x 
       status: under test */
    //uint8_t dIn1[14] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn2[10] = {0x12, 0x34, 0x56, 0x77, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    rsa_divide(dIn1, sizeof(dIn1), dIn2, sizeof(dIn2), quo, &quoLen, rem, &remLen);
    printf("Quotient is:\n");
    for (idx = 0; idx < quoLen; idx++)
    {
        printf("%x", quo[idx]);
    }
    printf("\n");
    printf("Remainder is:\n");
    for (idx = 0; idx < remLen; idx++)
    {
        printf("%x", rem[idx]);
    }
    printf("\n");
#endif
#if 0 //incomplete -need to continue
    uint8_t idx;
    /*
    uint8_t dOut[32];
    uint8_t dIn1[32] = {0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    */

    //uint8_t dOut[8];
    //uint8_t dIn1[2] = {0xFF, 0xFF};//, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    //uint8_t dIn2[4] = {0xFF, 0xFF, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /*
    Expected result: 0x666F.....
       */
    uint8_t dOut[14];
    uint8_t dIn1[2] = {0x01, 0x0B};//, 0xFF, 0xFF};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dIn2[1] = {0x04};//, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    uint8_t outLen;
    outLen = rsa_calculate_exponent(dIn1, 2, dIn2, 1, dOut);
    for (idx = 0; idx < outLen; idx++)
    {
        printf("%x", dOut[idx]);
    }
    printf("\n");
#endif

#if 0
    /*
        Ref: https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
        Ref: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        Ref: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        ## Verified test cases ##
        SHA256("")
        0x e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

        SHA256("hello world")
        big-endian --> 0xb9274db983e4d93d7522ea5faab7ddae3ef84c4ee80537aacf78890e9cdefe2
        little-endian --> 0xb94d27b9934d3e8a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

        SHA224("")
        0x d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
        after omitting h7 -> 0xd14a28c2a3a2bc947612bb288234c415a2b01f828ea62a

        SHA224("The quick brown fox jumps over the lazy dog")
        0x 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525
        after omitting h7 -> 0x73e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38b

        SHA224("The quick brown fox jumps over the lazy dog.")
        0x 619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c
        after omitting h7 -> 0x619cba8e8e5826e9b8c519ca5c68f4fb653e8a3d8aa04b

        SHA512("abc")
        O/P: 0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea2a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce8e2a9ac94fa54ca49f

        SHA512("hello world")
        O/P: 0x309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f

        SHA512("")
        0x cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e

        SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
        0x8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e490f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be99

        SHA384("")
        0x 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
        SHA512/224("")
        0x 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4
        SHA512/256("")
        0x c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a
        SHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
        0x3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a

    */
    uint8_t idx;
    uint8_t *digest = calloc(1, 64);
    /*uint8_t digest2[] = {0xb9,0x27,0x4d,0xb9, 0x83, 0xe4, 0xd9, 0x3d, 75, 0x22, 0xea, 0x5f, 0xaa, 0xb7, 0xdd,
                         0xae, 0x3e, 0xf8, 0x4c, 0x4e, 0xe8, 0x05, 0x37, 0xaa, 0xcf, 0x78, 0x89, 0x0e, 0x9c, 0xde, 0xfe, 0x2};//calloc(1, 32); */
    //uint8_t *dIn = "The quick brown fox jumps over the lazy dog";
    //uint8_t *dIn = "hello world";
    //uint8_t *dIn = "";
    //uint8_t *dIn = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t *dIn = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    //uint8_t *dIn = "abc";
    //uint8_t *dIn = "The quick brown fox jumps over the lazy dog.";
    //uint8_t dIn[10] = {0x01, 0x0B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    //sha256_compute_hash(dIn, strlen(dIn), digest);
    //sha224_compute_hash(dIn, strlen(dIn), digest);
    sha512_compute_hash(dIn, strlen(dIn), digest);
    //sha512t_compute_hash(dIn, strlen(dIn), SHA_512_256, digest);
    //convert8_endianess(digest, digest2, 32);
    printf("The SHA256 hash is:\n");
    for (idx = 0; idx < 64; idx++)
    {
        printf("%x", digest[idx]);
    }
    printf("\n");
    free(digest);
    //free(digest2);
    //printf("%x\n",modulo32_add(0x68656c6c, 0xcee195cb));
#endif

#if 1
/*
SHA3-224("")
6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
SHA3-256("")
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
SHA3-384("")
0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
SHA3-512("")
a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
SHAKE128("", 256)
7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
SHAKE256("", 512)
46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be
SHAKE128("The quick brown fox jumps over the lazy dog", 256)
f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e
SHAKE128("The quick brown fox jumps over the lazy dof", 256)
853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c
*/

#endif

#if 0 // yet to be tested
    tls13_clientHello_t *ch = calloc(1, (sizeof(tls13_clientHello_t) + 200));
    uint16_t size;
    //size = tls13_prepareClientHello(ch);
    uint8_t *disp;
    disp = (uint8_t *)ch;
    for(int idx = 0; idx < size; idx++){
        printf("%x", disp[idx]);
    }
    printf("\n");
#endif

#if 1
#include "tls13_sm.h"
tls13_context_t *ctx = calloc(1, sizeof(tls13_context_t));
ctx->role = TLS13_CLIENT;
ctx->server_ip = 270000;
ctx->server_port = 40000;
ctx->client_ip = 27000;
ctx->client_port = 40000;
memcpy(ctx->server_hostname, "www.google.com", strlen("www.google.com"));
ctx->server_hostname_len = strlen("www.google.com");
tls13_init(ctx);
tls13_close(ctx);
free(ctx);
#endif

    return 0;
}