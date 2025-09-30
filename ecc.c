#include <string.h>
#include "math.h"
#include "ecc.h"


/* Ref:
 1. https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
 2. https://cse.iitkgp.ac.in/~debdeep/pres/TI/ecc.pdf
 3. https://medium.com/@abhiveerhome/building-elliptic-curve-cryptography-ecc-from-scratch-7b28e3b27531
*/

static void point_multiplication(const ecc_point_t *dIn, uint8_t *num, uint32_t numLen,  uint8_t a_param, ecc_point_t *dOut);
static void point_addition(const ecc_point_t *dIn1, const ecc_point_t *dIn2,  uint8_t *a_param, ecc_point_t *dOut);
static bool is_point_at_infinity(const ecc_point_t *dIn1, const ecc_point_t *dIn2);
static bool are_points_equal(const ecc_point_t *dIn1, const ecc_point_t *dIn2);

static bool is_point_at_infinity(const ecc_point_t *dIn1, const ecc_point_t *dIn2)
{
    bool retVal;
    uint8_t *temp = calloc(1, dIn2->yLen);
    retVal = is_equal(dIn1->x, dIn1->xLen, dIn2->x, dIn2->xLen);
    not(dIn2->y, temp, dIn2->yLen);
    retVal |= is_equal(dIn1->y, dIn1->yLen, temp, dIn2->xLen);
    free(temp);
    return retVal;
}

static bool are_points_equal(const ecc_point_t *dIn1, const ecc_point_t *dIn2)
{
    bool retVal;
    retVal = is_equal(dIn1->x, dIn1->xLen, dIn2->x, dIn2->xLen);
    return retVal;
}

static void point_addition(const ecc_point_t *dIn1, const ecc_point_t *dIn2, uint8_t *a_param, ecc_point_t *dOut)
{
    bool status = false;
    ecc_point_t *temp;
    uint32_t dOutLen1;
    uint32_t dOutLen2;
    uint32_t r_xLen;
    uint32_t r_yLen;
    uint8_t two[] = {0x02};
    uint8_t three[] = {0x03};

    uint8_t *lambda1 = calloc(1, (dIn1->xLen + dIn2->yLen));
    uint8_t *lambda2 = calloc(1, (dIn1->xLen + dIn2->yLen));
    uint8_t *r_x = calloc(1, (dIn1->xLen + dIn2->yLen));
    uint8_t *r_y = calloc(1, (dIn1->xLen + dIn2->yLen));
    /* Case 1: P or Q is the point at infinity */

    /* Case 2: P = -Q (result is point at infinity) */
    status = is_point_at_infinity(dIn1, dIn2);
    if(status == true){
        memcpy(dOut, dIn1, sizeof(dIn1));
    }

    /* Case 3: P = Q (point doubling) */
    status = are_points_equal(dIn1, dIn2);
    if(status == true){
        /* lambda = (3 * P.x * P.x + A_PARAM) / (2 * P.y); */
        multiply(dIn1->x, dIn1->xLen, dIn1->x, dIn1->xLen, lambda1, &dOutLen1);
        multiply(three, sizeof(three), lambda1, dOutLen1, lambda1, &dOutLen1);
        add(a_param, sizeof(a_param), lambda1, dOutLen1, lambda1, &dOutLen1);

        multiply(two, sizeof(two), dIn2->y, dIn2->yLen, lambda2, &dOutLen2);
        divide(lambda1, dOutLen1, lambda2, dOutLen2, lambda2, &dOutLen2, NULL, 0);
    }
    /* Case 4: P != Q (distinct point addition) */
    else{
        /* lambda = (Q.y - P.y) / (Q.x - P.x); */
        subtract(dIn2->y, dIn2->yLen, dIn1->y, dIn2->yLen, lambda1, &dOutLen1);
        subtract(dIn2->x, dIn2->xLen, dIn1->x, dIn2->xLen, lambda2, &dOutLen2);
        divide(lambda1, dOutLen1, lambda2, dOutLen2, lambda2, &dOutLen2, NULL, 0);
    }

    /*  r.x = lambda * lambda - P.x - Q.x;
        r.y = lambda * (p.x - r.x) - p.y;
    */
    multiply(lambda2, dOutLen2, lambda2, dOutLen2, lambda1, &dOutLen1);
    subtract(lambda1, dOutLen1, dIn1->x, dIn1->xLen, r_x, &r_xLen);
    subtract(r_x, r_xLen, dIn2->x, dIn2->xLen, r_x, &r_xLen);

    subtract(dIn1->x, dIn1->xLen, r_x, r_xLen, lambda1, &dOutLen1);
    multiply(lambda2, dOutLen2, lambda1, dOutLen1, r_y, &r_yLen);
    subtract(r_y, r_yLen, dIn2->y, dIn2->yLen, r_y, &r_yLen);

    memcpy(&dOut->x, r_x, r_xLen);
    dOut->xLen = r_xLen;
    memcpy(&dOut->y, r_y, r_yLen);
    dOut->yLen = r_yLen;

    free(lambda1);
    free(lambda2);
    free(r_x);
    free(r_y);
}

/* assuming all data are in big endian format */
static void point_multiplication(const ecc_point_t *dIn, uint8_t *num, uint32_t numLen, uint8_t a_param, ecc_point_t *dOut)
{
    uint32_t tNumLen = 0;
    uint8_t idx;
    ecc_point_t temp;
    memcpy(&temp, dIn, sizeof(dIn));
    while(tNumLen < numLen)
    {
        for(idx = 8; idx > 0; idx++){

            /* Point doubling */
            point_addition(&temp, &temp, a_param, dOut);

            if((num[tNumLen] >> (idx - 1)) == 1){
                /* point addition */
                point_addition(dOut, dIn, a_param, dOut);
            }
            memcpy(&temp, dOut, sizeof(dOut));
        }
        tNumLen++;
    }
}
#define aParam 0x54321
void ecc_generate_keypair(const ecc_point_t *genPoint, uint8_t *aNum, uint32_t aNumLen, uint8_t *bNum, uint32_t bNumLen, ecc_keypair_t *pair1, ecc_keypair_t *pair2)
{
    ecc_point_t temp1;
    ecc_point_t temp2;
    ecc_point_t temp3;
    ecc_point_t temp4;

    temp1.x = calloc(1, genPoint->xLen);
    temp2.x = calloc(1, genPoint->xLen);
    temp3.x = calloc(1, genPoint->xLen);
    temp4.x = calloc(1, genPoint->xLen);
    temp1.y = calloc(1, genPoint->yLen);
    temp2.y = calloc(1, genPoint->yLen);
    temp3.y = calloc(1, genPoint->yLen);
    temp4.y = calloc(1, genPoint->yLen);


    /* Pair #1: Public Key*/
    point_multiplication(genPoint, aNum, aNumLen, aParam, &temp1);

    /* Pair #2: Public Key*/
    point_multiplication(genPoint, bNum, bNumLen, aParam, &temp2);

    /* Pair #1: Private Key*/
    point_multiplication(&temp2, aNum, aNumLen, aParam, &temp3);

    /* Pair #2: Private Key*/
    point_multiplication(&temp1, bNum, bNumLen, aParam, &temp4);

    memcpy(pair1->pubKey, &temp1, sizeof(temp1));
    memcpy(pair1->privKey, &temp3, sizeof(temp3));
    memcpy(pair2->pubKey, &temp2, sizeof(temp2));
    memcpy(pair2->privKey, &temp4, sizeof(temp4));

    free(&temp1.x);
    free(&temp2.x);
    free(&temp3.x);
    free(&temp4.x);
    free(&temp1.y);
    free(&temp2.y);
    free(&temp3.y);
    free(&temp4.y);
}

void ecc_encrypt(const uint8_t *dIn, const uint8_t *key, uint8_t *dOut)
{

}

void ecc_decrypt(const uint8_t *dIn, const uint8_t *key, uint8_t *dOut)
{
    
}
