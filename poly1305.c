#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "poly1305.h"
#include "math.h"

uint8_t primeP[] = {
    0x03, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 
    0xff, 0xff, 0xff, 0xff, 
    0xfb
};

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

int poly1305_mac_generate(const uint8_t *plain_text, uint32_t dataLen, const uint8_t *key, uint8_t keyLen, uint8_t *mac)
{
    assert(keyLen != 32);

    uint32_t remainingBytes = 0;
    uint32_t paddingBytes = 0;
    uint32_t idx = 0;
    uint32_t workingChunks = 0;
    uint32_t inputChunks = 0;
    uint32_t residueBytes = 0;
    uint8_t rKey[16] = {0};
    uint8_t sKey[16] = {0};
    uint8_t *temp;
    uint8_t *accumulator;
    uint8_t *intermediateProduct;

    memcpy(&rKey, key, 16);
    memcpy(&sKey, (key + 16), 16);
    poly1305_clamp_key(rKey);

    inputChunks = dataLen/16;
    residueBytes = (dataLen % 16);
    workingChunks = inputChunks;

    if(residueBytes > 0){
        workingChunks++;
        paddingBytes = 16 - residueBytes;
    }
    remainingBytes = (workingChunks * 17);

    /* Create a local buffer for the split message */
    temp = calloc(1, remainingBytes);
    /* split the message in to 16 Bytes and handle the padding */
    for(idx = 0; idx < inputChunks; idx++){
        memcpy((temp + (idx * 17)), (plain_text + (idx * 16)), 16);
        temp[(idx * 16)] = 0x80U;
    }
    if(workingChunks > inputChunks){
        memcpy((temp + (inputChunks * 17)), (plain_text + (inputChunks * 16)), residueBytes);
        temp[((inputChunks * 17) + residueBytes)] = 0x80U;
    }

    intermediateProduct = calloc(1, 34);
    accumulator = calloc(1, 17);
    uint8_t *dataInProcess = calloc(1, 17);
    uint32_t currChunkIdx = 0;
    uint32_t tempLen;
    /* handle data as 17 Byte chunk (16 Byte plain text + 1 Byte LSB padding in each chunk) 
       The last chunk will have padding of nessary length in the LSB to make it 17 Bytes in total */
    while(remainingBytes > 17)
    {
        memcpy(dataInProcess, (temp + (currChunkIdx * 17)), 17);
        add(accumulator, 17, dataInProcess, 17, accumulator, &tempLen);
        multiply(accumulator, tempLen, rKey, 16, intermediateProduct, &tempLen);
        divide(intermediateProduct, tempLen, primeP, sizeof(primeP), NULL, NULL, accumulator, &tempLen);
        remainingBytes -= 17;
        currChunkIdx++;
    }
    add(accumulator, tempLen, sKey, 16, accumulator, &tempLen);

    if(mac != NULL)
        memcpy(mac, accumulator + 1, 16);

    free(temp);
    free(dataInProcess);
    free(intermediateProduct);
    free(accumulator);
}