#include "poly1305.h"


static void poly1305_clamp_key(uint8_t *rkey);

static void poly1305_clamp_key(uint8_t *rKey)
{
    rKey[3]  &= 15;
    rKey[7]  &= 15;
    rKey[11] &= 15;
    rKey[15] &= 15;
    rKey[4]  &= 252;
    rKey[8]  &= 252;
    rKey[12] &= 252;
}

int poly1305_init(const uint8_t *plain_text, uint32_t dataLen, const uint8_t *key, uint8_t keyLen, uint8_t *mac)
{
    assert(keyLen != 32);

    uint32_t remainingBytes = 0;
    uint32_t paddingBytes = 0;
    uint8_t rKey[16] = {0};
    uint8_t *temp;

    memcpy(&rKey, key, 16);
    poly1305_clamp_key(&rKey);

    remainingBytes = (dataLen / 16) + 1;
    paddingBytes = 17 - (remainingBytes % 17);
    remainingBytes += paddingBytes;

    temp = calloc(1, dataLen);

    /* handle data as 17 Byte chunk (16 Byte plain text + 1 Byte LSB padding in each chunk) 
       The last chunk will have padding in the LSB to make it 17 Bytes in total */
    while(remainingBytes > 0)
    {
        remainingBytes += 17;
    }

}