#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "sha.h"
#include "math.h"

uint64_t RC[24] = 
{
    0x0000000000000001,
    0x000000008000808B,
    0x0000000000008082,
    0x800000000000008B,
    0x800000000000808A,
    0x8000000000008089,
    0x8000000080008000,
    0x8000000000008003,
    0x000000000000808B,
    0x8000000000008002,
    0x0000000080000001,
    0x8000000000000080,
    0x8000000080008081,
    0x000000000000800A,
    0x8000000000008009,
    0x800000008000000A,
    0x000000000000008A,
    0x8000000080008081,
    0x0000000000000088,
    0x8000000000008080,
    0x0000000080008009,
    0x0000000080000001,
    0x000000008000000A,
    0x8000000080008008
};

static void theta(uint64_t **dIn);
static void rho_pi_chi(uint64_t **dIn, uint8_t round);
//static void pi
//static void chi 
static uint64_t iota(uint64_t dIn, uint8_t round);

static void theta(uint64_t **dIn)
{
    uint64_t C[5];
    uint64_t D[5];
    uint8_t xIdx;
    uint8_t yIdx;

    for(xIdx = 0; xIdx < 5; xIdx++){

        C[xIdx] = modulo64_add(modulo64_add(modulo64_add(dIn[xIdx][0], dIn[xIdx][1]), modulo64_add(dIn[xIdx][2], dIn[xIdx][3])), dIn[xIdx][4]);
        D[xIdx] = modulo64_add(C[xIdx -1], ROTR64(C[xIdx+1], 1));
        for(yIdx = 0; yIdx < 5; yIdx++){

            dIn[xIdx][yIdx] = modulo64_add(dIn[xIdx][yIdx], D[xIdx]);
        }
    }
}

static void rho_pi_chi(uint64_t **dIn, uint8_t round)
{
    uint8_t xIdx;
    uint8_t yIdx;
    uint8_t yTemp;
    uint8_t t = round;

    uint64_t B[5][25];
    for(xIdx = 0; xIdx < 5; xIdx++){
        for(yIdx = 0; yIdx < 5; yIdx++){

            yTemp = (2 * xIdx) + (3 * yIdx);
            B[yIdx][yTemp] = ROTR64(dIn[xIdx][yIdx], (((t+1)*(t+2))/2));
        }
    }
    //memcpy(dOut, B, sizeof(B));
    for(xIdx = 0; xIdx < 5; xIdx++){
        for(yIdx = 0; yIdx < 5; yIdx++){

            dIn[xIdx][yIdx] = modulo64_add(B[xIdx][yIdx], ((~B[xIdx+1][yIdx]) & B[xIdx+2][yIdx]));
        }
    }
}

static uint64_t iota(uint64_t dIn, uint8_t round)
{
    uint64_t retVal;
    assert(round < 24);
    retVal = modulo64_add(dIn, RC[round]);
    return retVal;
}

void sha3_compute_hash(uint8_t *message, uint64_t messageLen, sha3_type_e sha_type, uint8_t *digest)
{
    //uint64_t msgLen_in_bits;
    uint64_t idx;
    uint8_t xIdx;
    uint8_t yIdx;
    //uint64_t offset = 0;
    uint32_t r_bits = 0;
    uint32_t c_bits = 0;
    uint8_t r_bytes = 0;
    uint8_t c_bytes = 0;

    uint64_t keccakState[5][5];

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
    /* padding done on LSB side */
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

        for(xIdx = 5; xIdx > 0; xIdx--){
            for(yIdx = 5; yIdx > 0; yIdx--){
                memcpy(&keccakState[xIdx-1][yIdx-1], (messageChunk + ((5 - xIdx) * 8) + ((5 - yIdx) * 8)), 8);
            }
        }

        for (idx = 0; idx < 24; idx++)
        {
            theta(&keccakState);
            rho_pi_chi(&keccakState, idx);
            iota(&keccakState, idx);

        }
        /* copy keccak state array to message chunk*/
        for(xIdx = 5; xIdx > 0; xIdx--){
            for(yIdx = 5; yIdx > 0; yIdx--){
                memcpy((messageChunk + ((5 - xIdx) * 8) + ((5 - yIdx) * 8)), &keccakState[xIdx-1][yIdx-1], 8);
            }
        }
        remainingLen -= r_bytes;
    }

}