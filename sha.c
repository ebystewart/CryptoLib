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
uint32_t h_224[8] =
{
    0xc1059ed8, 
    0x367cd507, 
    0x3070dd17, 
    0xf70e5939, 
    0xffc00b31, 
    0x68581511, 
    0x64f98fa7, 
    0xbefa4fa4
};

uint32_t h_256[8] =
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

uint64_t h_384[8] =
{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

uint64_t h_512[8] =
{
    0x6a09e667f3bcc908, 
    0xbb67ae8584caa73b, 
    0x3c6ef372fe94f82b, 
    0xa54ff53a5f1d36f1, 
    0x510e527fade682d1, 
    0x9b05688c2b3e6c1f, 
    0x1f83d9abfb41bd6b, 
    0x5be0cd19137e2179
};

uint64_t h_512_224[8] =
{
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 
    0x0f6d2b697bd44da8, 0x77e36f7304C48942, 0x3f9d85a86a1d36C8, 0x1112e6ad91d692a1
};

uint64_t h_512_256[8] =
{
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddC81c52ca2
};


/* Initialize array of round constants:
   (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
*/
uint32_t k_256[64] =
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

 /* SHA-512 round constants */

uint64_t k_512[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void sha256_compute_hash(uint8_t *message, uint32_t messageLen, uint8_t *digest)
{
    uint32_t s0;
    uint32_t s1;
    uint8_t idx;
    uint8_t offset = 0;

    //assert(messageLen > 0); /* hash of 0 message length possible */
    uint8_t paddingLen = 64 - (messageLen % 64);
    if((messageLen % 64) > 55)
        offset = 64 ; // round off to 64

    uint32_t remainingLen = messageLen + paddingLen + offset; /* in Bytes */
    uint8_t chunkIdx = 0;
    printf("Received: %u, padding: %u, offset: %u, Total: %u\n", messageLen, paddingLen, offset, remainingLen);
    printf("The received message of length %u inlcuding padding is:\n", messageLen);
    for(idx = 0; idx < messageLen; idx++){
        printf("%x", message[idx]);
    }
    printf("\n");
    uint32_t *w = (uint32_t *)calloc(1, (64 *4)); /* Schedule array */
    //uint32_t *working_var = (uint32_t *)calloc(1, 8*4);
    //uint32_t *hash = (uint32_t *)calloc(1, 8*4);
    uint32_t working_var[8] = {0};
    uint32_t hash[8] = {0};

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
    /*  append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
        such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer>, 
        (the number of bits will be a multiple of 512)
    */
    // temp_msg[remainingLen-7] = 0x00U;
    // temp_msg[remainingLen-6] = 0x00U;
    // temp_msg[remainingLen-5] = 0x00U;
    // temp_msg[remainingLen-4] = 0x00U;
    uint32_t msgLen_in_bits = messageLen * 8;
    temp_msg[remainingLen-4] = (uint8_t)((msgLen_in_bits >> 24) & 0xFFU);
    temp_msg[remainingLen-3] = (uint8_t)((msgLen_in_bits >> 16) & 0xFFU);
    temp_msg[remainingLen-2] = (uint8_t)((msgLen_in_bits >> 8) & 0xFFU);
    temp_msg[remainingLen-1] = (uint8_t)(msgLen_in_bits & 0xFFU);

    printf("The total message of length %u inlcuding padding is:\n", remainingLen);
    for(idx = 0; idx < remainingLen; idx++){
        printf("%x", temp_msg[idx]);
    }
    printf("\n");

    uint8_t *messageChunk = calloc(1, 64);

    /* break messages in to 512 bits chunk */
    while(remainingLen > 0)
    {
        memcpy(messageChunk, (temp_msg + (chunkIdx * 64)), 64);

        printf("The chunk %u is:\n", chunkIdx);
        for(idx = 0; idx < 64; idx++){
            printf("%x", messageChunk[idx]);
        }
        printf("\n");
        printf("%x\n", w[0]);
        /* copy the chunk to the first 64 bytes of schedule array */
        memcpy((uint8_t *)w, messageChunk, 64);
        remainingLen -= 64;
        printf("w (with message chunk) of length %u is:\n", 64);
        for(idx = 0; idx < 16; idx++){
            printf("%x", w[idx]);
        }
        printf("\n");
        convert32_endianess(w, w, 16);
        //printf("%x\n", w[0]);
        //printf("%x\n", w[15]);
        printf("w after endianess change (with message chunk) of length %u is:\n", 64);
        for(idx = 0; idx < 16; idx++){
            printf("%x", w[idx]);
        }
        printf("\n");

        /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array */
        for(idx = 16; idx < 64; idx++){
            s0 = (ROTR(w[idx-15],7)) ^ (ROTR(w[idx-15],18)) ^ (w[idx-15] >> 3);
            s1 = (ROTR(w[idx-2],17)) ^ (ROTR(w[idx-2],19)) ^ (w[idx-2] >> 10);
            w[idx] = modulo32_add(w[idx-16], modulo32_add(s0, modulo32_add(w[idx-7], s1)));
        }

        printf("w of length %u is:\n", 64);
        for(idx = 0; idx < 64; idx++){
            printf("%x", w[idx]);
        }
        printf("\n");

        /* Initialize working variables to current hash value */
        memcpy(working_var, h_256, sizeof(h_256));
        printf("working var of length %u is:\n", sizeof(h_256));
        for(idx = 0; idx < sizeof(h_256)/4; idx++){
            printf("%x", working_var[idx]);
        }
        printf("\n");

        uint32_t S1, ch, temp1, S0, maj,temp2;
        /* Compression function main loop */
        for(idx = 0; idx < 64; idx++){

            S1 = (ROTR(working_var[4],6)) ^ (ROTR(working_var[4],1)) ^ (ROTR(working_var[4],25));
            ch = (working_var[4] & working_var[5]) ^ ((!working_var[4]) & working_var[5]);
            temp1 = modulo32_add(working_var[7], modulo32_add(S1, modulo32_add(ch, modulo32_add(k_256[idx], w[idx]))));
            S0 = (ROTR(working_var[0],2)) ^ (ROTR(working_var[0],13)) ^ (ROTR(working_var[0],22));
            maj = (working_var[0] & working_var[1]) ^ (working_var[0] & working_var[2]) ^ (working_var[1] & working_var[3]);
            temp2 = modulo32_add(S0, maj);
     
            working_var[7] = working_var[6];
            working_var[6] = working_var[5];
            working_var[5] = working_var[4];
            working_var[4] = modulo32_add(working_var[3], temp1);
            working_var[3] = working_var[2];
            working_var[2] = working_var[1];
            working_var[1] = working_var[0];
            working_var[0] = modulo32_add(temp1, temp2);
        }
    
        /* Add the compressed chunk to the current hash value */
        memcpy(hash, h_256, sizeof(h_256));
        hash[0] = modulo32_add(hash[0], working_var[0]);
        hash[1] = modulo32_add(hash[1], working_var[1]);
        hash[2] = modulo32_add(hash[2], working_var[2]);
        hash[3] = modulo32_add(hash[3], working_var[3]);
        hash[4] = modulo32_add(hash[4], working_var[4]);
        hash[5] = modulo32_add(hash[5], working_var[5]);
        hash[6] = modulo32_add(hash[6], working_var[6]);
        hash[7] = modulo32_add(hash[7], working_var[7]);

        chunkIdx++;
    }
    /* Produce the final hash value (big-endian) */
    memcpy(digest, hash, sizeof(hash));
    free(w);
    //free(working_var);
    //free(hash);
    free(temp_msg);
    free(messageChunk);
}

void sha224_compute_hash(uint8_t *message, uint32_t messageLen, uint32_t *digest)
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
        memcpy(working_var, h_224, sizeof(h_224));

        uint32_t S1, ch, temp1, S0, maj,temp2;
        /* Compression function main loop */
        for(idx = 0; idx < 64; idx++){

            S1 = (ROTR(working_var[4],6)) ^ (ROTR(working_var[4],1)) ^ (ROTR(working_var[4],25));
            ch = (working_var[4] & working_var[5]) ^ ((!working_var[4]) & working_var[5]);
            temp1 = working_var[7] + S1 + ch + k_256[idx] + w[idx];
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
        memcpy(hash, h_224, sizeof(h_224));
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
    memcpy(digest, hash, (sizeof(hash) - 4));
}

void sha512_compute_hash(uint8_t *message, uint32_t messageLen, uint32_t *digest)
{
    uint64_t w[80]; /* Schedule array */
    uint64_t working_var[8];
    uint64_t hash[8];
    uint64_t s0;
    uint64_t s1;
    uint64_t idx;
    uint64_t offset = 0;

    uint64_t paddingLen = 128 - (messageLen % 128);
    if((paddingLen % 128) > (55 + 64))
        offset = 128 ; // round off to 128 Bytes

    uint64_t remainingLen = messageLen + paddingLen + offset; /* in Bytes */
    uint32_t chunkIdx = 0;

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

    uint32_t *messageChunk = calloc(1, 128);

    /* break messages in to 512 bits chunk */
    while(remainingLen > 0)
    {
        memcpy(messageChunk, (temp_msg + (chunkIdx * 128)), 128);

        /* copy the chunk to the first 64 bytes of schedule array */
        memcpy(w, messageChunk, 128);
        remainingLen -= 128;

        /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array */
        for(idx = 0; idx < 80; idx++){
            s0 = (ROTR(w[idx-15],1)) ^ (ROTR(w[idx-15],8)) ^ (w[idx-15] >> 7);
            s1 = (ROTR(w[idx-2],19)) ^ (ROTR(w[idx-2],61)) ^ (w[idx-2] >> 6);
            w[idx] = w[idx-16] + s0 + w[idx-7] + s1;
        }

        /* Initialize working variables to current hash value */
        memcpy(working_var, h_512, sizeof(h_512));

        uint64_t S1, ch, temp1, S0, maj,temp2;
        /* Compression function main loop */
        for(idx = 0; idx < 80; idx++){

            S1 = (ROTR(working_var[4],14)) ^ (ROTR(working_var[4],18)) ^ (ROTR(working_var[4],41));
            ch = (working_var[4] & working_var[5]) ^ ((!working_var[4]) & working_var[5]);
            temp1 = working_var[7] + S1 + ch + k_256[idx] + w[idx];
            S0 = (ROTR(working_var[0],28)) ^ (ROTR(working_var[0],34)) ^ (ROTR(working_var[0],39));
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
        memcpy(hash, h_512, sizeof(h_512));
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

void sha384_compute_hash(uint8_t *message, uint32_t messageLen, uint32_t *digest)
{
    uint64_t w[80]; /* Schedule array */
    uint64_t working_var[8];
    uint64_t hash[8];
    uint64_t s0;
    uint64_t s1;
    uint64_t idx;
    uint64_t offset = 0;

    uint64_t paddingLen = 128 - (messageLen % 128);
    if((paddingLen % 128) > (55 + 64))
        offset = 128 ; // round off to 128 Bytes

    uint64_t remainingLen = messageLen + paddingLen + offset; /* in Bytes */
    uint32_t chunkIdx = 0;

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

    uint32_t *messageChunk = calloc(1, 128);

    /* break messages in to 512 bits chunk */
    while(remainingLen > 0)
    {
        memcpy(messageChunk, (temp_msg + (chunkIdx * 128)), 128);

        /* copy the chunk to the first 64 bytes of schedule array */
        memcpy(w, messageChunk, 128);
        remainingLen -= 128;

        /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array */
        for(idx = 0; idx < 80; idx++){
            s0 = (ROTR(w[idx-15],1)) ^ (ROTR(w[idx-15],8)) ^ (w[idx-15] >> 7);
            s1 = (ROTR(w[idx-2],19)) ^ (ROTR(w[idx-2],61)) ^ (w[idx-2] >> 6);
            w[idx] = w[idx-16] + s0 + w[idx-7] + s1;
        }

        /* Initialize working variables to current hash value */
        memcpy(working_var, h_384, sizeof(h_384));

        uint64_t S1, ch, temp1, S0, maj,temp2;
        /* Compression function main loop */
        for(idx = 0; idx < 80; idx++){

            S1 = (ROTR(working_var[4],14)) ^ (ROTR(working_var[4],18)) ^ (ROTR(working_var[4],41));
            ch = (working_var[4] & working_var[5]) ^ ((!working_var[4]) & working_var[5]);
            temp1 = working_var[7] + S1 + ch + k_256[idx] + w[idx];
            S0 = (ROTR(working_var[0],28)) ^ (ROTR(working_var[0],34)) ^ (ROTR(working_var[0],39));
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
        memcpy(hash, h_384, sizeof(h_384));
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
    memcpy(digest, hash, (sizeof(hash) - 8));
}