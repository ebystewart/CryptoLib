#ifndef _RSA_H_
#define _RSA_H_

/* Reference:
    1. https://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/RSAmath.html
*/

typedef enum{
    RSA_1024 = 1024U,
    RSA_2048 = 2048U,
    RSA_3072 = 3072U,
    RSA_4096 = 4096U
}rsa_keyLen_e;

int rsa_generate_prime(rsa_keyLen_e keyLen, uint8_t *prime);

#endif