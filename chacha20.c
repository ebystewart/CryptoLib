#include <stdlib.h>
#include <string.h>
#include "chacha20.h"
#include "math.h"

#define ROT_L32(x, n) x = (x << n) | (x >> (32 - n))
#define QUARTERROUND(a, b, c, d)       \
    a += b;  d ^= a;  ROT_L32(d, 16);  \
    c += d;  b ^= c;  ROT_L32(b, 12);  \
    a += b;  d ^= a;  ROT_L32(d,  8);  \
    c += d;  b ^= c;  ROT_L32(b,  7)

static void chacha20_initStateMatrix(uint32_t *key, uint32_t *nounce, uint32_t counter, uint32_t *state);
static void chacha20_PerformQuarterRound(uint32_t *block);

static void chacha20_initStateMatrix(uint32_t *key, uint32_t *nounce, uint32_t counter, uint32_t *state)
{
    uint32_t *stateMatrix = (uint32_t *)calloc(1, 16*4);

    /* Fill the first row with the string "expand 32-byte k", broken into four 32-bit words */
    stateMatrix[0] = 0x65787061;
    stateMatrix[1] = 0x6E642033;
    stateMatrix[2] = 0x322D6279; 
    stateMatrix[3] = 0x7465206B;

    /* The second and third rows are filled with the 256-bit key */
    stateMatrix[4] = key[0];
    stateMatrix[5] = key[1];
    stateMatrix[6] = key[2];
    stateMatrix[7] = key[3];
    stateMatrix[8] = key[4];
    stateMatrix[9] = key[5];
    stateMatrix[10] = key[6];
    stateMatrix[11] = key[7];

    /* The first word of the last row is filled with the 32-bit counter */
    stateMatrix[12] = counter;

    /* The remaining words in the last row are filled with the 96-bit nonce */
    stateMatrix[13] = nounce[0];
    stateMatrix[14] = nounce[1];
    stateMatrix[15] = nounce[2];

    memcpy(state, stateMatrix, 16*4);
    free(stateMatrix);
}

static void chacha20_PerformQuarterRound(uint32_t *block)
{
    /*
        a += b;  d ^= a;  d <<<= 16;
        c += d;  b ^= c;  b <<<= 12;
        a += b;  d ^= a;  d <<<=  8;
        c += d;  b ^= c;  b <<<=  7;
    */
    for (int i = 0; i < 10; i++) { // 20 rounds, 2 rounds per loop.
        QUARTERROUND(block[0], block[4], block[ 8], block[12]); // column 0
        QUARTERROUND(block[1], block[5], block[ 9], block[13]); // column 1
        QUARTERROUND(block[2], block[6], block[10], block[14]); // column 2
        QUARTERROUND(block[3], block[7], block[11], block[15]); // column 3
        QUARTERROUND(block[0], block[5], block[10], block[15]); // diagonal 1
        QUARTERROUND(block[1], block[6], block[11], block[12]); // diagonal 2
        QUARTERROUND(block[2], block[7], block[ 8], block[13]); // diagonal 3
        QUARTERROUND(block[3], block[4], block[ 9], block[14]); // diagonal 4
    }
}

int chacha20_encrypt(uint8_t *plain_text, uint32_t dataLen, uint32_t *key, uint32_t *nounce, uint32_t counter, uint8_t *cipher_text, uint32_t *dOutLen)
{
    uint32_t *state = calloc(1, 64);

    chacha20_initStateMatrix(key, nounce, counter, state);

    /* scramble the state using quarter-round function */
    chacha20_PerformQuarterRound(state);

    /* Now XOR the scrambled block with the 512 bits of the plain text stream */
    xor2((uint8_t *)state, plain_text, 64, cipher_text);

    free(state);
}