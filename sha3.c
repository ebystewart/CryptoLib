#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "sha.h"


void sha3_compute_hash(uint8_t *message, uint64_t messageLen, sha3_type_e sha_type, uint8_t *digest)
{
    uint64_t msgLen_in_bits;
    uint64_t idx;
    uint64_t offset = 0;

    uint64_t paddingLen = 200 - (messageLen % 200);
    if((messageLen % 200) > 111)
        offset = 200 ; // round off to 128 Bytes

    msgLen_in_bits = messageLen * 8;
    uint64_t remainingLen = messageLen + paddingLen + offset; /* in Bytes */
    uint32_t chunkIdx = 0;

    uint8_t *temp_msg = calloc(1, remainingLen);
    memcpy(temp_msg, message, messageLen);

    /* Do the padding here if message length is not a multiple of 64 Bytes (512 Bits) */
    if((paddingLen > 0) && (offset > 0)) {
        /* append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512 */
        memset(&temp_msg[messageLen], 0, (paddingLen + offset));
        /* Step #1: append a single '1' bit */
        temp_msg[messageLen] = 0x80U;
    }
    else{
        /* append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512 */
        memset(&temp_msg[messageLen], 0, paddingLen);
        temp_msg[messageLen] = 0x80U;
    }

    temp_msg[remainingLen-1] = (uint8_t)0x01;

    uint8_t *messageChunk = calloc(1, 200);/* each message chunk is of 1600 bits i.e. r+c = 1600 */
    /* Initialize working variables to current hash value */
    if(sha_type == SHA3_256){
        /* TBI */
    }
    else if (sha_type == SHA3_224){
        /* TBI */
    }
    else if (sha_type == SHA3_512){
        /* TBI */
    }
    else if (sha_type == SHA3_384){
        /* TBI */
    }
    else
        assert(0);

    /* break messages in to 1600 bits chunk */
    while(remainingLen > 0)
    {
        remainingLen -= 200;
    }
}