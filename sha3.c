#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "sha.h"
#include "math.h"


void sha3_compute_hash(uint8_t *message, uint64_t messageLen, sha3_type_e sha_type, uint8_t *digest)
{
    //uint64_t msgLen_in_bits;
    uint64_t idx;
    //uint64_t offset = 0;
    uint32_t r_bits = 0;
    uint32_t c_bits = 0;
    uint8_t r_bytes = 0;
    uint8_t c_bytes = 0;

    if(sha_type == SHA3_256){
        r_bits = 1088; /* 136 Bytes */
        c_bits = 512;  /*  64 Bytes */
    }
    else if (sha_type == SHA3_224){
        r_bits = 1152; /*144 Bytes  */
        c_bits = 448;  /* 56 bytes */
    }
    else if (sha_type == SHA3_512){
        r_bits = 576;  /*  72 Bytes */
        c_bits = 1024; /* 128 Bytes */
    }
    else if (sha_type == SHA3_384){
        r_bits = 832; /* 104 Bytes */
        c_bits = 768; /*  96 Bytes */
    }
    else
        assert(0);
    
    r_bytes = r_bits/8;
    c_bytes = c_bits/8;

    uint64_t paddingLen =  r_bytes - (messageLen % r_bytes);
    
    uint64_t remainingLen = messageLen + paddingLen; /* in Bytes */
    uint32_t chunkIdx = 0;

    uint8_t *temp_msg = calloc(1, remainingLen);
    memcpy(temp_msg, message, messageLen);

    /* Do the padding here if message length is not a multiple of r_bytes */
    if(paddingLen > 0) {
        /* append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512 */
        memset(&temp_msg[messageLen], 0, paddingLen);
        /* Step #1: append a single '1' bit */
        temp_msg[messageLen] = 0x80U;
        /* In case messageLen equals (remainingLen -1), we use tha | operator */
        temp_msg[remainingLen-1] |= (uint8_t)0x01U;
    }
    else{
        assert(0);
    }

    uint8_t *messageChunk = calloc(1, 200);/* each message chunk is of 1600 bits i.e. r+c = 1600 */
    memcpy(messageChunk, temp_msg, r_bytes);

    /* break messages in to 1600 bits chunk */
    while(remainingLen > 0)
    {
        xor(messageChunk, (temp_msg + (chunkIdx * r_bytes)), r_bytes);

        remainingLen -= r_bytes;
    }
}