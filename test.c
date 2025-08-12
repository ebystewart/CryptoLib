#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

uint8_t in[16] = {0x63, 0x2F, 0xAF, 0xA2,
               0xEB, 0x93, 0xC7, 0x20,
               0x9F, 0x92, 0xAB, 0xCB,
               0xA0, 0xC0, 0x30, 0x2B};

uint8_t out[16] = {0};
uint8_t temp[16] = {0};
uint8_t temp2[16] = {0};
uint8_t round_key[16] = {0};

uint8_t plain_text[16] = {0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F};
uint8_t key[16] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75};
uint8_t initVal[16] = {0};

int main(int arc, char ** argv)
{
    int nRound = 0;
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
    aes_encrypt_init(AES_CBC, AES_128, key, initVal, plain_text, out);

    for (int i = 0; i < 16; i++)
    {
        printf("%x", out[i]);
    }
    printf("\n");
    aes_encrypt_update(AES_CBC, out, temp, key, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");

    aes_encrypt_end(AES_CBC, temp, temp2, AES_128);
    for (int i = 0; i < 16; i++)
    {
        printf("%x", temp[i]);
    }
    printf("\n");
#if 0
    aes_inverseTranspose(temp, out);
    for(int i=0; i < 16; i++){
        printf("%x", out[i]);
    }
    printf("\n");
#endif
    return 0;
}