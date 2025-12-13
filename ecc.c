#include <string.h>
#include "math.h"
#include "ecc.h"


/* Ref:
 1. https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
 2. https://cse.iitkgp.ac.in/~debdeep/pres/TI/ecc.pdf
 3. https://medium.com/@abhiveerhome/building-elliptic-curve-cryptography-ecc-from-scratch-7b28e3b27531
*/

uint8_t pList[2][32] =
{
    { 
      0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed 
    },
    { 
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F 
    },
};

uint8_t nList[1][32] =
{
    {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
    },
};

uint8_t xList[1][32] =
{
    {
        0x09
    },
};

uint8_t yList[1][32] =
{
    {
        0x20, 0xae, 0x19, 0xa1, 0xb8, 0xa0, 0x86, 0xb4, 0xe0, 0x1e, 0xdd, 0x2c, 0x77, 0x48, 0xd1, 0x4c, 
        0x92, 0x3d, 0x4d, 0x7e, 0x6d, 0x7c, 0x61, 0xb2, 0x29, 0xe9, 0xc5, 0xa2, 0x7e, 0xce, 0xd3, 0xd9
    },
};

static ecc_curve_params_t curve_table[] =
{
    /* Curve25519 */
    {
        0x76d06, /* a */
        0x01,    /* b */
        &pList[1][0],
        32,
        &nList[1][0],
        32,
        &xList[1][0],
        1,
        &yList[1][0],
        32,        
    }
};

uint8_t aParam[4] = {0x00, 0x54, 0x32, 0x10};

static void point_multiplication(const ecc_point_t *dIn, uint8_t *num, uint32_t numLen,  uint8_t *a_param, ecc_point_t *dOut);
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
static void point_multiplication(const ecc_point_t *dIn, uint8_t *num, uint32_t numLen, uint8_t *a_param, ecc_point_t *dOut)
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

void ecc_init_genPoint(ecc_curve_t curveType, ecc_point_t *genPoint)
{
    /* Look up the Curev data table and fetch the x and y coordinates */
    genPoint->x = calloc(1, curve_table[curveType].xLen);
    genPoint->y = calloc(1, curve_table[curveType].yLen);
    memcpy(genPoint->x, curve_table[curveType].x, curve_table[curveType].xLen);
    memcpy(genPoint->y, curve_table[curveType].y, curve_table[curveType].yLen);
}

void ecc_destroy_genPoint(ecc_curve_t curveType, ecc_point_t *genPoint)
{
    free(genPoint->x);
    free(genPoint->y);
    free(genPoint);
}

void ecc_generate_keypair(const ecc_point_t *genPoint, ecc_keypair_t *keyPair)
{
    ecc_point_t temp;
    uint32_t privKeyLen = genPoint->xLen;

    uint8_t privKey[] = {0x43, 0x21, 0x43, 0x21, 0x43, 0x21};// a randon number of length aNumLen (in actuals)

    temp.x = calloc(1, genPoint->xLen);
    temp.y = calloc(1, genPoint->yLen);

    /* Public Key - used to be a point on the elliptic curve */
    point_multiplication(genPoint, privKey, privKeyLen, aParam,  &temp);

    memcpy(keyPair->pubKey, &temp, sizeof(temp));
    memcpy(keyPair->privKey, privKey, privKeyLen);
    keyPair->privKeyLen = privKeyLen;

    free(temp.x);
    free(temp.y);
}

void ecc_exchange_init(const ecc_point_t *genPoint, ecc_keypair_t *keyPair){

    ecc_keypair_t *key;
    key = calloc(1, ((3* genPoint->xLen) + (3* sizeof(uint32_t))));
    key->privKeyLen = genPoint->xLen;
    key->pubKey->xLen = genPoint->xLen;
    key->pubKey->yLen = genPoint->xLen;

    ecc_generate_keypair(genPoint, keyPair);
    free(key);
}

void ecc_exchange_update(const ecc_keypair_t *keyPair, ecc_point_t *dataForExchange)
{
    ecc_point_t *temp;

    uint32_t privKeyLen = keyPair->privKeyLen;

    temp->x = calloc(1, keyPair->pubKey->xLen);
    temp->y = calloc(1, keyPair->pubKey->yLen);

    /* We get the public key of other party and do point multiplication with its own private key */
    point_multiplication(keyPair->pubKey, keyPair->privKey, keyPair->privKeyLen, aParam, temp);

    // Is this sufficient?
    memcpy(dataForExchange, temp, sizeof(temp));
    memcpy(dataForExchange->x, temp->x, temp->xLen);
    memcpy(dataForExchange->y, temp->y, temp->yLen);

    free(temp->x); 
    free(temp->y);
}

bool ecc_validate_Secret(const ecc_point_t *exchangedData, const ecc_keypair_t *keyPair, const ecc_point_t *receivedPubKey)
{
    uint8_t *inverse;
    ecc_point_t *temp;
    int status;
    bool retVal = false;

    temp->x = calloc(1, exchangedData->xLen);
    temp->y = calloc(1, exchangedData->yLen);

    /* (exchangeData on both sides) a Kb = b Ka */
    /* a b R = b a R */
    /* The received point PK should be divided by private key (a/b) and the Generator point R */

    /* find inverse of private key - k⁻¹ such that k * k⁻¹ ≡ 1 (mod n), 
       where n is the order of the cyclic group generated by the base point of the elliptic curve */
    uint8_t *privInverse = calloc(1, keyPair->privKeyLen);
    negative_of((uint8_t *)&keyPair->privKeyLen, privInverse, keyPair->privKeyLen);

    /* Do point multiplication - this gives a R [OR] b R */
    point_multiplication(exchangedData, privInverse, keyPair->privKeyLen, aParam, temp);

    /* Temp should match with the public key of the other party */
    status = memcmp(receivedPubKey->x, temp->x, temp->xLen);
    status |= memcmp(receivedPubKey->y, temp->y, temp->yLen);
    
    if(status == 0)
        retVal = true;

    return retVal;
}


void ecc_extract_secret(const uint8_t *dIn1, uint8_t *dIn2, uint32_t dInLen, uint32_t a_param, uint8_t *dOut)
{
    ecc_point_t dKeyPair;
    dKeyPair.x = dIn1;
    dKeyPair.xLen = dInLen;
    dKeyPair.y = NULL;
    dKeyPair.yLen = 0;
    point_multiplication(&dKeyPair, dIn2, dInLen, &a_param, dOut);
}

void ecc_encrypt(const uint8_t *dIn, const uint8_t *key, uint8_t *dOut)
{

}

void ecc_decrypt(const uint8_t *dIn, const uint8_t *key, uint8_t *dOut)
{
    
}
