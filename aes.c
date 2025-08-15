#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "aes.h"

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

// The AES S-box lookup table
const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x0e, 0xb5, 0x1d, 0x62, 0xe5, 0x7a,
    0x9c, 0x71, 0x0d, 0x33, 0x2b, 0x07, 0x7e, 0xd6, 0x26, 0x63, 0x18, 0x83, 0xce, 0xee, 0x9a, 0x4b,
    0xef, 0x0c, 0xad, 0x8c, 0x78, 0xc6, 0x8f, 0x14, 0x3c, 0x1b, 0x4b, 0xf1, 0x59, 0x4b, 0x20, 0x9c, 
    0x2d, 0x29, 0x1c, 0x5f, 0x6f, 0x4a, 0x04, 0x2c, 0xc8, 0x19, 0x80, 0xae, 0x2a, 0xce, 0xed, 0x75,
    0x78, 0x1b, 0x6e, 0x4c, 0x5a, 0x76, 0x3a, 0x47, 0x30, 0x24, 0x55, 0x69, 0x0e, 0x65, 0x99, 0x4a,
    0x6d, 0x73, 0x2f, 0x3a, 0x90, 0x45, 0x00, 0x20, 0x8b, 0x10, 0x9b, 0x88, 0x4a, 0x5a, 0x2e, 0xba,
    0x44, 0x3d, 0x2c, 0x34, 0x8e, 0x19, 0x99, 0x30, 0x4c, 0xc1, 0x3f, 0x25, 0x0e, 0x70, 0x5a, 0x80
};

static uint8_t s_box[256];

static uint8_t aes_job_id;
static uint8_t aes_job_slot[64];

static uint8_t aes_get_job_id(void);

static void aes_close_job_id(uint8_t job_id);

/* Static functions */
int aes_get_round_key(const uint8_t *key_in, uint8_t *round_key, uint8_t nRound);

/* /brief  s-box is generated using a */
int aes_create_s_box(void);

int aes_substitute_bytes(uint8_t *in, uint8_t *out);

int aes_inverse_substitute_bytes(uint8_t *in, uint8_t *out);

int aes_shift_rows(uint8_t *in, uint8_t *out);

int aes_inverse_shift_rows(uint8_t *in, uint8_t *out);

int aes_mix_columns(uint8_t *in, uint8_t *out);

int aes_inverse_mix_columns(uint8_t *in, uint8_t *out);

int add_round_key(uint8_t *in, uint8_t *out);

int aes_transpose(uint8_t *in, uint8_t *out);

int aes_inverseTranspose(uint8_t *in, uint8_t *out);

static uint8_t aes_get_job_id(void)
{
    uint8_t idx;
    aes_job_slot[aes_job_id++] = aes_job_id;
    return aes_job_id;
}

static void aes_close_job_id(uint8_t job_id)
{
    aes_job_slot[aes_job_id] = 0;
}

/*
From:
{0,   1,  2,  3}
{4,   5,  6,  7}
{8,   9, 10, 11}
{12, 13, 14, 15}

To:
{0, 4,  8, 12}
{1, 5,  9, 13}
{2, 6, 10, 14}
{3, 7, 11, 15}
*/
int aes_transpose(uint8_t *in, uint8_t *out)
{
    uint8_t idx;
    for(idx = 0; idx < 4; idx++){
        out[idx]      = in[(idx * 4)];       /* 0 -> 0, 4 -> 1, 8 -> 2, 12 -> 3 */
        out[idx + 4]  = in[1 + (idx * 4)];   /* 1->4, 5->5, 9->6, 13->7 */
        out[idx + 8]  = in[2 + (idx * 4)];   /* 2->8, 6->9, 10->10, 14->11 */
        out[idx + 12] = in[3 + (idx * 4)];   /* 3->12, 7->13, 11->14, 15->15 */
    }
}

int aes_inverseTranspose(uint8_t *in, uint8_t *out)
{
    uint8_t idx;
    for(idx = 0; idx < 4; idx++){
        out[(idx * 4)]     = in[idx];       /* 0 <- 0, 4 <- 1, 8 <- 2, 12 <- 3 */
        out[1 + (idx * 4)] = in[idx + 4];   /* 1<-4, 5<-5, 9<-6, 13<-7 */
        out[2 + (idx * 4)] = in[idx + 8];   /* 2<-8, 6<-9, 10<-10, 14<-11 */
        out[3 + (idx * 4)] = in[idx + 12];  /* 3<-12, 7<-13, 11<-14, 15<-15 */
    }
}

int aes_get_round_key(const uint8_t *key_in, uint8_t *round_key, uint8_t nRound)
{
    uint8_t idx;
    uint8_t w0[4] = {0};
    uint8_t w1[4] = {0};
    uint8_t w2[4] = {0};
    uint8_t w3[4] = {0};
    uint8_t w4[4] = {0};
    uint8_t w5[4] = {0};
    uint8_t w6[4] = {0};
    uint8_t w7[4] = {0};
    uint8_t gw3[4] = {0};
   
    /* arrange 4 byte wise */
    for(idx = 0; idx < 4; idx++){
        w0[idx] = key_in[idx];
        w1[idx] = key_in[idx + 4];
        w2[idx] = key_in[idx + 8];
        w3[idx] = key_in[idx + 12];
    }
    /* circular byte left shift*/
    for(idx = 0; idx < 3; idx++){
        gw3[idx] = w3[idx + 1];
    }
    gw3[3] = w3[0];

    printf("The byte left shifted w3 is %x %x %x %x\n", gw3[0], gw3[1], gw3[2], gw3[3]);

    for(idx = 0; idx < 4; idx++){
        gw3[idx] = sbox[(((gw3[idx] >> 4) & 0x0F) * 16) + (gw3[idx] & 0x0F)];
    }
    printf("The byte substituted w3 is %x %x %x %x\n", gw3[0], gw3[1], gw3[2], gw3[3]);
    /* matrix addition of gw3 with round constant array */
    if(nRound < 9)
        gw3[0] = gw3[0] ^ (0x01U << (nRound - 1));
    else if(nRound == 9)
        gw3[0] = gw3[0] ^ 0x1B;
    else if (nRound == 10)
        gw3[0] = gw3[0] ^ 0x36;

    printf("The round constant added w3 is %x %x %x %x\n", gw3[0], gw3[1], gw3[2], gw3[3]);
    
    /* w(n) = w(n-4) ^ w(n-1) */
    for(idx = 0; idx < 4; idx++){
        w4[idx] = w0[idx] ^ gw3[idx];
        w5[idx] = w1[idx] ^ w4[idx];
        w6[idx] = w2[idx] ^ w5[idx];
        w7[idx] = w3[idx] ^ w6[idx];
    }

    /* re-arrange 4 byte wise in to output buffer */
    for(idx = 0; idx < 4; idx++){
        round_key[idx]      = w4[idx];
        round_key[idx + 4]  = w5[idx];
        round_key[idx + 8]  = w6[idx];
        round_key[idx + 12] = w7[idx];
    }  
}

#if 0
int aes_create_s_box(void)
{
	uint8_t p = 1, q = 1;
	
	/* loop invariant: p * q == 1 in the Galois field (GF) */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		s_box[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	s_box[0] = 0x63;
}
#else

int aes_create_s_box(void)
{
    uint8_t value;
    uint8_t mulInv_value;
    uint8_t columns;
    uint8_t rows;
    bool temp[8];
    uint8_t mx1;
    memset(s_box, 0, sizeof(s_box));

    uint16_t M = 0x11B;
    for(value = 0; value < 256; value++){

        /* Calculate the multiplicative inverse of input value using Euclidean & Extended Euclidean algorithm */
        uint16_t A = A % M; // Ensure A is within the range [0, M-1]
        for (int X = 1; X < M; X++) {
            // Check if (A * X) % M equals 1
            if (((A * X) % M) == 1) {
                mulInv_value = X; // X is the modular multiplicative inverse
                break;
            }
        }

        /* Apply affine transform on the multiplicative inverse of the input */
        for(rows = 0; rows < 8; rows++){
            mx1 = 0x8FU;
            for(columns = 0; columns < 8; columns++){
                
                temp[rows] ^= (bool)(0x01U & ((mx1 >> columns) & (mulInv_value >> columns)));
                //printf("%x", temp[rows]);
            }
            //printf("\n");
            if(rows > 0)
                mx1 = (0x8FU >> rows) | (((0x8FU >> (rows - 1)) & 0x01U) << 8);
        }

        for(rows = 0; rows < 8; rows++){

            temp[rows] ^= (0xC6U >> (7 - rows));
            s_box[mulInv_value] |= ((uint8_t)temp[rows] << rows);
        }
        //printf("The index is %x and the value is %x\n", value, s_box[value]);
    }
    s_box[0] = 0x63;
    return 0;
}
#endif

int aes_substitute_bytes(uint8_t *in, uint8_t *out)
{
    uint8_t idx;
    /* S-Box substitution */
    printf("S-box substitution of bytes\n");
    for (idx = 0; idx < 16; idx++)
    {
        out[idx] = sbox[(((in[idx] >> 4) & 0x0F) * 16) + (in[idx] & 0x0F)];
        printf("%x", out[idx]);
    }
    printf("\n");
    return 0;
}

int aes_inverse_substitute_bytes(uint8_t *in, uint8_t *out)
{
    uint8_t idx;
    /* Inverse S-Box substitution */
    printf(" Inverse S-box substitution of bytes\n");
    for (idx = 0; idx < 16; idx++)
    {
        out[idx] = inv_sbox[(((in[idx] >> 4) & 0x0F) * 16) + (in[idx] & 0x0F)];
        printf("%x", out[idx]);
    }
    printf("\n");
    return 0;
}

/* expects a matrix arranged stream of bytes of following byte order
{0, 4,  8, 12}
{1, 5,  9, 13}
{2, 6, 10, 14}
{3, 7, 11, 15}
*/
int aes_shift_rows(uint8_t *in, uint8_t *out)
{
    uint8_t idx;
    for(idx = 0; idx < 16; idx++){
        if((idx % 4) == 0)
            out[idx] = in[idx];
    }
    /* second row - left shift by one Byte */
    out[13] = in[1];
    out[9]  = in[13];
    out[5]  = in[9];
    out[1]  = in[5];

    /* third row - left shift by 2 Bytes */
    out[14] = in[6];
    out[10] = in[2];
    out[6]  = in[14];
    out[2]  = in[10];

    /* fourth row - left shift by 3 Bytes */
    out[15] = in[11];
    out[11] = in[7];
    out[7]  = in[3];
    out[3]  = in[15];
}

int aes_inverse_shift_rows(uint8_t *in, uint8_t *out)
{
    uint8_t idx;
    for(idx = 0; idx < 16; idx++){
        if((idx % 4) == 0)
            out[idx] = in[idx];
    }
    /* second row - left shift by one Byte */
    out[1]  = in[13];
    out[13] = in[9];
    out[9]  = in[5];
    out[5]  = in[1];

    /* third row - left shift by 2 Bytes */
    out[6]  = in[14];
    out[2]  = in[10];
    out[14] = in[6];
    out[10] = in[2];

    /* fourth row - left shift by 3 Bytes */
    out[11] = in[15];
    out[7]  = in[11];
    out[3]  = in[7];
    out[15] = in[3];
}

static uint8_t aes_galoisPolyMultiply(uint8_t constPoly, uint8_t y){

    uint8_t out;
    uint16_t yi;

    if(constPoly == 1){
        out = constPoly * y;
    }
    else if (constPoly == 2){
        yi = ( y << 1);
        if(yi > 255){
            yi = (uint8_t)yi ^ 0x1B;
        }
        out = (uint8_t)yi;
    }
    else if (constPoly == 3){
        yi = ( y << 1);
        yi ^= y;
        if(yi > 255){
            yi = (uint8_t)yi ^ 0x1B;
        }
        out = (uint8_t)yi;
    }
        
    return out;
}

int aes_mix_columns(uint8_t *in, uint8_t *out)
{
    uint8_t matrix[4][4] =  {
                                {2, 3, 1, 1 },
                                {1, 2, 3, 1 },
                                {1, 1, 2, 3 },
                                {3, 1, 1, 2 }
                            };
    uint8_t input[4][4] = {0};
    uint8_t output[4][4] = {0};
    int x;
    int y;

    /* Copy the input to a 4*4 matrix */
    for(x = 0; x < 4; x++){
        for(y = 0; y < 4; y++){
            input[x][y] = in[x + (4*y)];
            //printf("[%d,%d]:%x", x, y, in[x + (4*y)]);
        }
        //printf("\n");
    }

    /* Do the matrix multiplication */
    int k = 0;
    for(x = 0; x < 4; x++){
        for(y = 0; y < 4; y++){
            for(k = 0; k < 4; k++){
                output[x][y] ^= aes_galoisPolyMultiply(matrix[x][k], input[k][y]);
#if 0
                if(matrix[x][k] < 2)
                    output[x][y] ^= (matrix[x][k] * input[k][y]);

                else if (matrix[x][k] == 2){

                    if(input[k][y] < 0x80)
                        output[x][y] ^= (matrix[x][k] * input[k][y]);
                    else
                        output[x][y] ^= (((matrix[x][k] -1) * input[k][y]) ^ input[k][y]);
                }
                else if (matrix[x][k] == 3){

                    if(input[k][y] < 0x55)
                        output[x][y] ^= (matrix[x][k] * input[k][y]);
                    else if (input[k][y] < 0xAA)
                        output[x][y] ^= (((matrix[x][k] -1) * input[k][y]) ^ input[k][y]); 
                    else
                        output[x][y] ^= ((((matrix[x][k] -2) * input[k][y]) ^ input[k][y]) ^input[k][y]); 
                }
#endif
                //printf("[%d, %d]*[%d, %d]->[%d, %d]: matrix is %x, input is %x and output is %x\n", x, k, k, y, x, y, matrix[x][k], input[k][y], output[x][y]);
            }
        }
    }
    /* deserialize the matrix to output buffer */
        /* Copy the input to a 4*4 matrix */
    for(x = 0; x < 4; x++){
        for(y = 0; y < 4; y++){
            out[x + (4*y)] = output[x][y];
            //printf("%x", out[x + (4*y)]);
        }
        //printf("\n");
    }
}

int aes_inverse_mix_columns(uint8_t *in, uint8_t *out)
{
    uint8_t matrix[4][4] =  {
                                {2, 3, 1, 1 },
                                {1, 2, 3, 1 },
                                {1, 1, 2, 3 },
                                {3, 1, 1, 2 }
                            };
    uint8_t input[4][4] = {0};
    uint8_t output[4][4] = {0};
    int x;
    int y;

    /* Copy the input to a 4*4 matrix */
    for(x = 0; x < 4; x++){
        for(y = 0; y < 4; y++){
            input[x][y] = in[x + (4*y)];
            //printf("[%d,%d]:%x", x, y, in[x + (4*y)]);
        }
        //printf("\n");
    }

    /* Do the matrix multiplication */
    int k = 0;
    for(x = 0; x < 4; x++){
        for(y = 0; y < 4; y++){
            for(k = 0; k < 4; k++){
                output[x][y] ^= aes_galoisPolyMultiply(matrix[x][k], input[k][y]);
                //printf("[%d, %d]*[%d, %d]->[%d, %d]: matrix is %x, input is %x and output is %x\n", x, k, k, y, x, y, matrix[x][k], input[k][y], output[x][y]);
            }
        }
    }
    /* deserialize the matrix to output buffer */
        /* Copy the input to a 4*4 matrix */
    for(x = 0; x < 4; x++){
        for(y = 0; y < 4; y++){
            out[x + (4*y)] = output[x][y];
            //printf("%x", out[x + (4*y)]);
        }
        //printf("\n");
    }
}

int add_round_key(uint8_t *in, uint8_t *out)
{

}

int aes_encrypt_init(aes_mode_t mode, const uint8_t *initVal, const uint8_t *plain_text, 
    uint8_t *cipher_text, const uint8_t *key, aes_keylen_t keyLen)
{
    uint8_t idx;
    uint8_t job_id;
    uint8_t temp_data[16] = {0};
    uint8_t temp_key[16] = {0};

    /* add(XOR) Round key 0 with the plain text */
    for(idx = 0; idx < (keyLen / 8); idx++){
        /* XOR the IV with the plain text */
        temp_data[idx] = plain_text[idx] ^ initVal[idx];
        /* XOR the Key with the resultant data */
        cipher_text[idx] = temp_data[idx] ^ key[idx];
        //printf("XOR of %x & %x is %x\n", temp_data[idx], key[idx], cipher_text[idx]);
    }
    return aes_get_job_id();
}

int aes_encrypt_update(aes_mode_t mode, const uint8_t *plain_text, uint8_t *cipher_text, const uint8_t *key, uint8_t *rKey, aes_keylen_t keyLen)
{
    uint8_t round;
    uint8_t idx;
    uint8_t temp_data[16] = {0};
    uint8_t temp_data2[16] = {0};
    uint8_t temp_key[16] = {0};
    uint8_t round_key[16] = {0};
    uint8_t print_buff[16] = {0};


    round = 1;
    memcpy(temp_key, key, 16);
    //aes_transpose(plain_text, temp_data);
    memcpy(temp_data, plain_text, 16);

    while(round < 10){
        /* Calculate round key */
        aes_get_round_key(temp_key, round_key, round);
        printf("The round %d key is:\n", round);
        for(idx = 0; idx < 16; idx++){
            printf("%x", round_key[idx]);
        }
        printf("\n");

        /* S-Box substitution */
        printf("The round %d substituted matrix is:\n", round);
        for(idx = 0; idx < 16; idx++){
            temp_data2[idx] = sbox[(((temp_data[idx] >> 4) & 0x0F) * 16) + (temp_data[idx] & 0x0F)];
            printf("%x", temp_data2[idx]);
        }
        printf("\n");

        /* Shift rows */
        aes_shift_rows(temp_data2, temp_data);
        //aes_inverseTranspose(temp_data, print_buff);
        printf("The round %d row shifted matrix is:\n", round);
        for(idx = 0; idx < 16; idx++){
            printf("%x", temp_data[idx]);
        }
        printf("\n");   

        /* Mix columns */
        aes_mix_columns(temp_data, temp_data2);
        //aes_inverseTranspose(temp_data2, temp_data);
        printf("The round %d column mixed matrix is:\n", round);
        for(idx = 0; idx < 16; idx++){
            printf("%x", temp_data2[idx]);
        }
        printf("\n");  

        /* add round key */
        for(idx = 0; idx < 16; idx++){
            temp_data[idx] = temp_data2[idx] ^ round_key[idx];
        }
        printf("The round %d round key added maxtrix is:\n", round);
        for(idx = 0; idx < 16; idx++){
            printf("%x", temp_data[idx]);
        }
        printf("\n");
        //aes_inverseTranspose(temp_data, temp_data2);
        memcpy(temp_key, round_key, 16);
        round++;
    }
    memcpy(rKey, temp_key, 16);
    memcpy(cipher_text, temp_data, 16);
    //aes_inverseTranspose(temp_data, cipher_text);
    return 0;
}

int aes_encrypt_end(aes_mode_t mode, const uint8_t *plain_text, uint8_t *cipher_text, uint8_t *round_key, aes_keylen_t keyLen)
{
    uint8_t idx;
    uint8_t round;
    uint8_t temp_key[16] = {0};
    uint8_t temp_data[16] = {0};
    uint8_t temp_data2[16] = {0};

    round = (keyLen / 32) + 6;

    memcpy(temp_data, plain_text, 16);
    /* Calculate round key */
    aes_get_round_key(round_key, temp_key, 10);
    printf("The round %d key is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        printf("%x", temp_key[idx]);
    }
    printf("\n");

    /* S-Box substitution */
    printf("The round %d substituted mxtrix is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        temp_data2[idx] = sbox[(((temp_data[idx] >> 4) & 0x0F) * 16) + (temp_data[idx] & 0x0F)];
        printf("%x", temp_data2[idx]);
    }
    printf("\n");

    /* Shift rows */
    aes_shift_rows(temp_data2, temp_data);
    // aes_inverseTranspose(temp_data, print_buff);
    printf("The round %d row shifted matrix is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        printf("%x", temp_data[idx]);
    }
    printf("\n");

    /* add round key */
    for (idx = 0; idx < 16; idx++)
    {
        temp_data2[idx] = temp_data[idx] ^ temp_key[idx];
    }
    printf("The round %d round key added maxtrix is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        printf("%x", temp_data2[idx]);
    }
    printf("\n");
    memcpy(cipher_text, temp_data2, 16);
    return 0;
}

int aes_encrypt(aes_mode_t mode, uint8_t *initVal, uint8_t *plain_text, uint8_t *cipher_text, const uint8_t *key, aes_keylen_t keyLen)
{
    int retVal;
    uint8_t round_key[16] = {0};
    uint8_t temp[16] = {0};
    memcpy(round_key, key, 16);
    retVal = aes_encrypt_init(AES_CBC, initVal, plain_text, cipher_text, key, AES_128);
    if(retVal < 0)
        return -1;
    retVal = aes_encrypt_update(AES_CBC, cipher_text, temp, key, round_key, AES_128);
    if(retVal < 0)
        return -1;
    retVal = aes_encrypt_end(AES_CBC, temp, cipher_text, round_key, AES_128);
    if(retVal < 0)
        return -1;
}

int aes_decrypt_init(aes_mode_t mode, const uint8_t *initVal, const uint8_t *cipher_text, 
    uint8_t *plain_text, const uint8_t *key, aes_keylen_t keyLen)
{
    uint8_t idx;
    uint8_t round = 1;
    uint8_t temp[16] = {0};
    uint8_t round_key[16] = {0};

    memcpy(temp, key, 16);

    while(round < 11){
        aes_get_round_key(temp, round_key, round);
        memcpy(temp, round_key, 16);
        round++;
    }
    printf("The round %d key is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        printf("%x", round_key[idx]);
    }
    printf("\n");

    /* add(XOR) Round key 0 with the plain text */
    for (idx = 0; idx < (keyLen / 8); idx++)
    {
        /* XOR the IV with the plain text */
        temp[idx] = cipher_text[idx] ^ initVal[idx];
        /* XOR the Key with the resultant data */
        plain_text[idx] = temp[idx] ^ round_key[idx];
        // printf("XOR of %x & %x is %x\n", temp[idx], round_key[idx], plain_text[idx]);
    }
    return 0;
}

int aes_decrypt_update(aes_mode_t mode, const uint8_t *cipher_text, uint8_t *plain_text, const uint8_t *key, uint8_t *rKey, aes_keylen_t keyLen)
{

}

int aes_decrypt_end(aes_mode_t mode, const uint8_t *cipher_text, uint8_t *plain_text, uint8_t *key, aes_keylen_t keyLen)
{
    uint8_t idx;
    uint8_t round;
    uint8_t temp_data[16] = {0};
    uint8_t temp_data2[16] = {0};

    round = (keyLen / 32) + 6;

    memcpy(temp_data, cipher_text, 16);

    /* S-Box substitution */
    aes_inverse_substitute_bytes(temp_data, temp_data2);

    /* Shift rows */
    aes_inverse_shift_rows(temp_data2, temp_data);
    // aes_inverseTranspose(temp_data, print_buff);
    printf("The round %d row shifted matrix is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        printf("%x", temp_data[idx]);
    }
    printf("\n");

    /* add round key */
    for (idx = 0; idx < 16; idx++)
    {
        temp_data2[idx] = temp_data[idx] ^ key[idx];
    }
    printf("The round %d round key added maxtrix is:\n", round);
    for (idx = 0; idx < 16; idx++)
    {
        printf("%x", temp_data2[idx]);
    }
    printf("\n");
    memcpy(plain_text, temp_data2, 16);
    return 0;
}

int aes_decrypt(aes_mode_t mode, const uint8_t *initVal, const uint8_t *cipher_text, uint8_t *plain_text, const uint8_t *key, aes_keylen_t keyLen)
{
    int retVal;
    uint8_t round_key[16] = {0};
    uint8_t temp[16] = {0};
    uint8_t temp2[16] = {0};
    memcpy(round_key, key, 16);
    retVal = aes_decrypt_init(AES_CBC, initVal, cipher_text, temp, key, AES_128);
    if(retVal < 0)
        return -1;
    retVal = aes_decrypt_update(AES_CBC, temp, temp2, key, round_key, AES_128);
    if(retVal < 0)
        return -1;
    retVal = aes_decrypt_end(AES_CBC, temp2, plain_text, round_key, AES_128);
    if(retVal < 0)
        return -1;
}