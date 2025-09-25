#include "math.h"
#include "ecc.h"


/* Ref:
 1. https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
 2. https://cse.iitkgp.ac.in/~debdeep/pres/TI/ecc.pdf
 3. https://medium.com/@abhiveerhome/building-elliptic-curve-cryptography-ecc-from-scratch-7b28e3b27531
*/

static void point_multiplication(uint8_t *dIn1, uint8_t *dIn2, uint8_t *dOut);
static void point_addition(uint8_t *dIn1, uint8_t *dIn2, uint8_t *dOut);



