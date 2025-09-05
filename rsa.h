#ifndef _RSA_H_
#define _RSA_H_

/* Reference:
    1. https://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/RSAmath.html
*/

typedef enum{
    RSA_1024 = 1024U,
    RSA_2048 = 2048U,
    RSA_4096 = 4096U
}rsa_keyLen_e;

typedef enum{
    RSA_LESSER_THAN  = -1,
    RSA_EQUAL_TO     =  0,
    RSA_GREATER_THAN =  1
}rsa_comparison_e;

int rsa_generate_prime(rsa_keyLen_e keyLen, uint8_t *prime);
uint8_t rsa_find_exponent(const uint8_t *base, uint32_t baseLen, const uint8_t *power, uint32_t powerLen, uint8_t *out);

#endif