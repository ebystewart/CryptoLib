#ifndef _ECC_H_
#define _ECC_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/* 
    Ref: https://x25519.xargs.org/
*/
/*
# Elliptic curve parameters for secp256k1 (used in Bitcoin and Ethereum)
a = 0
b = 7
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (Gx, Gy)
*/

/*
# Curve25519 - 255-bit prime field Montgomery curve.
Name	Value
p	0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
a	0x76d06
b	0x01
G	(0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)
n	0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
h	0x08
*/
typedef enum{
    EC_ED25519,
    EC_ED448,
    EC_SECP256r1,
    EC_SECP384r1,
    EC_SECP521r1,
    EC_SECP256k1
}ecc_curve_t;

typedef struct{
    uint32_t a;
    uint32_t b;
    uint8_t *p;
    uint32_t pLen;
    uint8_t *n;
    uint32_t nLen;
    uint8_t *x;
    uint32_t xLen;
    uint8_t *y;
    uint32_t yLen;
}ecc_curve_params_t;

typedef struct {
    uint8_t *x;
    uint32_t xLen;
    uint8_t *y;
    uint32_t yLen;
}ecc_point_t;

typedef struct {
    ecc_point_t *pubKey;
    uint8_t *privKey;
    uint32_t privKeyLen;
}ecc_keypair_t;

void ecc_init_genPoint(ecc_curve_t curveType, ecc_point_t *genPoint);

void ecc_destroy_genPoint(ecc_curve_t curveType, ecc_point_t *genPoint);

void ecc_generate_keypair(const ecc_point_t *genPoint, ecc_keypair_t *keyPair);

void ecc_exchange_init(const ecc_point_t *genPoint, ecc_keypair_t *keyPair);

void ecc_exchange_update(const ecc_keypair_t *keyPair, ecc_point_t *dataForExchange);

bool ecc_validate_Secret(const ecc_point_t *exchangedData, const ecc_keypair_t *keyPair, const ecc_point_t *receivedPubKey);

void ecc_encrypt(const uint8_t *dIn, const uint8_t *key, uint8_t *dOut);

void ecc_decrypt(const uint8_t *dIn, const uint8_t *key, uint8_t *dOut);

void ecc_extract_secret(const uint8_t *dIn1, uint8_t *dIn2, uint32_t dInLen, uint32_t a_param, uint8_t *dOut);

#endif