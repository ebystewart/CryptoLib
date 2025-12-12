#include <assert.h>
#include "hmac.h"
#include "sha.h"

/* HMAC Algorithm:
Key Preparation (K0):

    Ensure the secret key (K) is the correct length for the hash function's block size (B bytes).
    If K's length equals B, set K0 = K.
    If K is longer than B, hash the key first (K0 = H(K)) and then pad the result with zeros to make it B bytes long.
    If K is shorter than B, pad it with zeros at the end to make it B bytes long.

Inner Hash Calculation:

    XOR the prepared key (K0) with a fixed "inner pad" (ipad) value, which is 0x36 repeated B times.
    Append the original message (M) to the result of the XOR operation: (K0 ⊕ ipad) || M.
    Apply the chosen hash function (H) to this combined string to produce an intermediate hash (inner hash).
    Formula: InnerHash = H(K0 ⊕ ipad || M)

Outer Hash Calculation (Final HMAC Generation):

    XOR the prepared key (K0) with a different fixed "outer pad" (opad) value, which is 0x5c repeated B times.
    Append the InnerHash value from the previous step to this new XOR result: (K0 ⊕ opad) || InnerHash.
    Apply the hash function (H) a second time to this entire concatenated string to produce the final HMAC.
    Formula: HMAC = H(K0 ⊕ opad || H(K0 ⊕ ipad || M)) 
*/
#define INNER_PAD 0x36
#define OUTER_PAD 0x5C

void hmac_generate(const uint8_t *message, size_t msgLen, const uint8_t *key, size_t keyLen, hmac_sha_e type, uint8_t *digest, size_t *digestLen)
{
    /* for HMAC, the key length should be greater than 128 bits */
    assert(keyLen >= 16);
    uint8_t idx = 0;
    uint8_t macLen = (uint8_t)type;
    uint8_t macType = (uint8_t)(type >> 8);
    uint8_t *tmpKey = calloc(1, macLen);
    uint8_t *tmpMsg = calloc(1, msgLen);
    uint8_t *innerHashIn  = calloc(1, (macLen + msgLen));
    uint8_t *innerHashOut = calloc(1, macLen);
    uint8_t *outerHashIn = calloc(1, (macLen + macLen));
    uint8_t *outerHashOut = calloc(1, macLen);

    if(keyLen < macLen)
    {
        uint8_t diff = macLen - keyLen;
        memcpy(tmpKey, key, keyLen);
        /* Pad it with zeros at the end to match the block size */
        memset((tmpKey + keyLen), 0, diff);
    }
    /* Need to revisit */
    else if(keyLen > macLen){
        if(macType == 0x02){
            sha2_compute_hash(key, keyLen, (sha2_type_e)macLen, tmpKey);
        }
        else if (macType == 0x03 || macType == 0x33){
            sha3_compute_hash(key, keyLen, (sha3_type_e)macLen, tmpKey);
        }
    }
    else{
        memcpy(tmpKey, key, keyLen);
    }
    /* Inner Hash Calculation */
    for(idx = 0; idx < macLen; idx++){
        innerHashIn[idx] = tmpKey[idx] ^ INNER_PAD;
    }
    memcpy((innerHashIn + macLen), message, msgLen);
    if(macType == 0x02){
        sha2_compute_hash(innerHashIn, (macLen + msgLen), (sha2_type_e)macLen, innerHashOut);
    }
    else if (macType == 0x03 || macType == 0x33){
        sha3_compute_hash(innerHashIn, (macLen + msgLen), (sha3_type_e)macLen, innerHashOut);
    }

    /* Outer Hash Calculation (Final MAC)*/
    for(idx = 0; idx < macLen; idx++){
        outerHashIn[idx] = tmpKey[idx] ^ OUTER_PAD;
    }
    memcpy((outerHashIn + macLen), innerHashOut, macLen);
    if(macType == 0x02){
        sha2_compute_hash(outerHashIn, (macLen + macLen), (sha2_type_e)macLen, outerHashOut);
    }
    else if (macType == 0x03 || macType == 0x33){
        sha3_compute_hash(outerHashIn, (macLen + macLen), (sha3_type_e)macLen, outerHashOut);
    }
    memcpy(digest, outerHashOut, macLen);
    *digestLen = macLen;
}

void hmac_hkdf_extract(const uint8_t *salt, uint32_t saltLen, const uint8_t *keyIn, uint32_t keyInLen, uint8_t *keyOut, uint32_t *keyOutLen)
{

}

void hmac_hkdf_expand_label(const uint8_t *keyIn, uint32_t keyInLen, const char *label, const uint8_t *ctx_hash, \
                            const uint32_t hashLen, uint8_t *keyOut, const uint32_t keyOutLen)
{

}