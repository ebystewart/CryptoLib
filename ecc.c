#include "math.h"
#include "ecc.h"


/* Ref:
 1. https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
 2. https://cse.iitkgp.ac.in/~debdeep/pres/TI/ecc.pdf
 3. https://medium.com/@abhiveerhome/building-elliptic-curve-cryptography-ecc-from-scratch-7b28e3b27531
*/

static void point_multiplication(const ecc_point_t *dIn1, const ecc_point_t *dIn2, ecc_point_t *dOut);
static void point_addition(const ecc_point_t *dIn1, const ecc_point_t *dIn2, ecc_point_t *dOut);
static bool is_point_at_infinity(const ecc_point_t *dIn1, const ecc_point_t *dIn2);
static bool are_points_equal(const ecc_point_t *dIn1, const ecc_point_t *dIn2);

static bool is_point_at_infinity(const ecc_point_t *dIn1, const ecc_point_t *dIn2)
{
    bool retVal;
    uint8_t *temp = calloc(1, dIn2->yLen);
    retVal = is_equal(&dIn1->x, dIn1->xLen, &dIn2->x, dIn2->xLen);
    not(&dIn2->y, dIn2->yLen, temp);
    retVal |= is_equal(&dIn1->y, dIn1->yLen, temp, dIn2->xLen);
    free(temp);
    return retVal;
}

static bool are_points_equal(const ecc_point_t *dIn1, const ecc_point_t *dIn2)
{

}

static void point_addition(const ecc_point_t *dIn1, const ecc_point_t *dIn2, ecc_point_t *dOut)
{
    bool status = false;
    ecc_point_t *temp;

    temp = calloc(1, (sizeof(dIn1) + dIn1->xLen + dIn2->yLen));
    /* Case 1: P or Q is the point at infinity */

    /* Case 2: P = -Q (result is point at infinity) */
    status = is_point_at_infinity(dIn1, dIn2);
    if(status == true){
        memcpy(dOut, dIn1, sizeof(dIn1));
    }

    /* Case 3: P = Q (point doubling) */
    status = are_points_equal(dIn1, dIn2);
    if(status == true){
        /* lambda = (3 * p.x * p.x + A_PARAM) / (2 * p.y); */

    }
    /* Case 4: P != Q (distinct point addition) */
    else{
        /* lambda = (q.y - p.y) / (q.x - p.x); */
    }

    /*  r.x = lambda * lambda - p.x - q.x;
        r.y = lambda * (p.x - r.x) - p.y;
    */
    memcpy(dOut, temp, sizeof(temp));
}



