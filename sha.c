#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sha.h"
#include "math.h"

    /* Initialize hash values:
        (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
    */
uint32_t h[8] =
{
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

/* Initialize array of round constants:
   (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
*/
uint32_t k[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void sha_compute_hash(uint8_t *message, uint32_t messageLen, sha_type_e sha_type, uint32_t *digest)
{
    uint32_t w[64]; /* Schedule array */
    uint32_t working_var[8];
    uint32_t hash[8];
    uint32_t s0;
    uint32_t s1;
    uint8_t idx;
    uint8_t offset = 0;

    uint8_t paddingLen = 64 - (messageLen % 64);
    if((paddingLen % 64) > 55)
        offset = 64 ; // round off to 64

    uint32_t remainingLen = messageLen + paddingLen + offset; /* in Bytes */
    uint8_t chunkIdx = 0;

    uint8_t *temp_msg = calloc(1, remainingLen);
    memcpy(temp_msg, message, messageLen);

    /* Do the padding here if message length is not a multiple of 64 Bytes (512 Bits) */
    if((paddingLen > 0) && (offset > 0)) {
        /* append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512 */
        memset(temp_msg[messageLen], 0, paddingLen);
        /* Step #1: append a single '1' bit */
        temp_msg[messageLen] = 0x80;
    }
    else{
        /* append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512 */
        memset(temp_msg[messageLen], 0, 56);
        temp_msg[messageLen] = 0x80U;
    }
    /*  append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
        such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer>, 
        (the number of bits will be a multiple of 512)
    */
    // temp_msg[remainingLen-7] = 0x00U;
    // temp_msg[remainingLen-6] = 0x00U;
    // temp_msg[remainingLen-5] = 0x00U;
    // temp_msg[remainingLen-4] = 0x00U;
    temp_msg[remainingLen-3] = (uint8_t)((messageLen >> 24) & 0xFFU);
    temp_msg[remainingLen-2] = (uint8_t)((messageLen >> 16) & 0xFFU);
    temp_msg[remainingLen-1] = (uint8_t)((messageLen >> 8) & 0xFFU);
    temp_msg[remainingLen] = (uint8_t)(messageLen & 0xFFU);

    uint32_t *messageChunk = calloc(1, 64);

    /* break messages in to 512 bits chunk */
    while(remainingLen > 0)
    {
        memcpy(messageChunk, (temp_msg + (chunkIdx * 64)), 64);

        /* copy the chunk to the first 64 bytes of schedule array */
        memcpy(w, messageChunk, 64);
        remainingLen -= 64;

        /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array */
        for(idx = 0; idx < 64; idx++){
            s0 = (ROTR(w[idx-15],7)) ^ (ROTR(w[idx-15],18)) ^ (w[idx-15] >> 3);
            s1 = (ROTR(w[idx-2],17)) ^ (ROTR(w[idx-2],19)) ^ (w[idx-2] >> 10);
            w[idx] = w[idx-16] + s0 + w[idx-7] + s1;
        }

        /* Initialize working variables to current hash value */
        memcpy(working_var, h, sizeof(h));

        uint32_t S1, ch, temp1, S0, maj,temp2;
        /* Compression function main loop */
        for(idx = 0; idx < 64; idx++){

            S1 = (ROTR(working_var[4],6)) ^ (ROTR(working_var[4],1)) ^ (ROTR(working_var[4],25));
            ch = (working_var[4] & working_var[5]) ^ ((!working_var[4]) & working_var[5]);
            temp1 = h + S1 + ch + k[idx] + w[idx];
            S0 = (ROTR(working_var[0],2)) ^ (ROTR(working_var[0],13)) ^ (ROTR(working_var[0],22));
            maj = (working_var[0] & working_var[1]) ^ (working_var[0] & working_var[2]) ^ (working_var[1] & working_var[3]);
            temp2 = S0 + maj;
     
            working_var[7] = working_var[6];
            working_var[6] = working_var[5];
            working_var[5] = working_var[4];
            working_var[4] = working_var[3] + temp1;
            working_var[3] = working_var[2];
            working_var[2] = working_var[1];
            working_var[1] = working_var[0];
            working_var[0] = temp1 + temp2;
        }
    
        /* Add the compressed chunk to the current hash value */
        memcpy(hash, h, sizeof(h));
        hash[0] = hash[0] + working_var[0];
        hash[1] = hash[1] + working_var[1];
        hash[2] = hash[2] + working_var[2];
        hash[3] = hash[3] + working_var[3];
        hash[4] = hash[4] + working_var[4];
        hash[5] = hash[5] + working_var[5];
        hash[6] = hash[6] + working_var[6];
        hash[7] = hash[7] + working_var[7];

        chunkIdx++;
    }
    /* Produce the final hash value (big-endian) */
    memcpy(digest, hash, sizeof(hash));
}