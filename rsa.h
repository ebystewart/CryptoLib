#ifndef _RSA_H_
#define _RSA_H_

/* Reference:
    1. https://www.cs.sjsu.edu/~stamp/CS265/SecurityEngineering/chapter5_SE/RSAmath.html
*/

typedef enum{
    RSA_1024,
    RSA_2048,
    RSA_3072,
    RSA_4096
}rsa_keyLen_e;;

#endif