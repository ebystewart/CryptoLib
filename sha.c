#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sha.h"

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


void sha_compute_hash(void)
{

    uint32_t w[64]; /* Schedule array */
    uint32_t working_var[8];
    uint32_t hash[8];
    uint32_t s0;
    uint32_t s1;
    uint8_t idx;
    uint32_t digest;

    uint32_t *messageChunk = calloc(1, 64);

    /* break messages in to 512 bits chunk */
    {
        /* copy the chunk to the first 64 bytes of schedule array */
        memcpy(w, messageChunk, 64);

        /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array */
        for(idx = 0; idx < 64; idx++){
            s0 = (ROTR(w[idx-15],7)) ^ (ROTR(w[idx-15],18)) ^ (w[idx-15] >> 3);
            s1 = (ROTR(w[idx-2],17)) ^ (ROTR(w[idx-2],19)) ^ (w[idx-2] >> 10);
            w[idx] = w[idx-16] + s0 + w[idx-7] + s1;
        }

        /* Initialize working variables to current hash value */
        memcpy(working_var, h, sizeof(h));

        /* Compression function main loop */
        for(idx = 0; idx < 64; idx++){
            uint32_t S1 = (ROTR(e,6)) ^ (ROTR(e,1)) ^ (ROTR(e,25));
            uint32_t ch = (e & f) ^ ((!e) & g)
            uint32_t temp1 = h + S1 + ch + k[idx] + w[idx];
            uint32_t S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
     
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
        #if 0
        h0 := h0 + a
        h1 := h1 + b
        h2 := h2 + c
        h3 := h3 + d
        h4 := h4 + e
        h5 := h5 + f
        h6 := h6 + g
        h7 := h7 + h
    
        /* Produce the final hash value (big-endian) */
        digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
        #endif
    }

    
}