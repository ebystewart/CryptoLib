#include <assert.h>
#include <string.h>
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
    uint8_t diff = 0;
    uint8_t macLen = (uint8_t)type;
    uint8_t hashClass = (uint8_t)(type >> 8);
    uint8_t tmpKeyLen = 0;

    if(hashClass == 0x02 && macLen <= 32){
        tmpKeyLen = 64;
    }
    else if (hashClass == 0x02 && macLen > 32){
        tmpKeyLen = 128;
    }
    else if (hashClass == 0x03 || hashClass == 0x33){
        if (macLen == 28)
            tmpKeyLen = 144;
        if (macLen == 32)
            tmpKeyLen = 136;
        if (macLen == 48)
            tmpKeyLen = 104;
        if (macLen == 64)
            tmpKeyLen = 72;                        
    }

    uint8_t *tmpKey = calloc(1, tmpKeyLen);
    uint8_t *tmpMsg = calloc(1, msgLen);
    uint8_t *innerHashIn  = calloc(1, (tmpKeyLen + msgLen));
    uint8_t *innerHashOut = calloc(1, macLen);
    uint8_t *outerHashIn  = calloc(1, (tmpKeyLen + macLen));
    uint8_t *outerHashOut = calloc(1, macLen);

    if(keyLen < tmpKeyLen)
    {
        diff = tmpKeyLen - keyLen;
        memcpy(tmpKey, key, keyLen);
        /* Pad it with zeros at the end to match the block size */
        memset((tmpKey + keyLen), 0, diff);
    }
    /* Need to revisit */
    else if(keyLen > tmpKeyLen){
        diff = tmpKeyLen - macLen;
        if(hashClass == 0x02){
            sha2_compute_hash(key, keyLen, (sha2_type_e)macLen, tmpKey);
        }
        else if (hashClass == 0x03){
            sha3_compute_hash(key, keyLen, (sha3_type_e)macLen, tmpKey);
        }
        else if(hashClass == 0x33)
        {
            sha3_compute_hash(key, keyLen, (sha3_type_e)type, tmpKey);
        }
        memset((tmpKey + macLen), 0, diff);
    }
    else{
        memcpy(tmpKey, key, keyLen);
    }
    /* Inner Hash Calculation */
    for(idx = 0; idx < tmpKeyLen; idx++){
        innerHashIn[idx] = tmpKey[idx] ^ INNER_PAD;
    }
    memcpy((innerHashIn + tmpKeyLen), message, msgLen);
    if(hashClass == 0x02){
        sha2_compute_hash(innerHashIn, (tmpKeyLen + msgLen), (sha2_type_e)macLen, innerHashOut);
    }
    else if (hashClass == 0x03 || hashClass == 0x33){
        sha3_compute_hash(innerHashIn, (tmpKeyLen + msgLen), (sha3_type_e)macLen, innerHashOut);
    }

    /* Outer Hash Calculation (Final MAC)*/
    for(idx = 0; idx < tmpKeyLen; idx++){
        outerHashIn[idx] = tmpKey[idx] ^ OUTER_PAD;
    }
    memcpy((outerHashIn + tmpKeyLen), innerHashOut, macLen);
    if(hashClass == 0x02){
        sha2_compute_hash(outerHashIn, (tmpKeyLen + macLen), (sha2_type_e)macLen, outerHashOut);
    }
    else if (hashClass == 0x03 || hashClass == 0x33){
        sha3_compute_hash(outerHashIn, (tmpKeyLen + macLen), (sha3_type_e)macLen, outerHashOut);
    }
    memcpy(digest, outerHashOut, macLen);
    *digestLen = macLen;
    /* Free allocated memories */
    free(tmpKey);
    free(tmpMsg);
    free(innerHashIn);
    free(innerHashOut);
    free(outerHashIn);
    free(outerHashOut);
}

/* Salt - optional and non-secret 
   Salt as key
   IKM(input Key Material) as Data/message
   Output is a Pseudo Random Key (PRK) 
*/
void hmac_hkdf_extract(const uint8_t *salt, uint32_t saltLen, const uint8_t *keyIn, uint32_t keyInLen, hmac_sha_e type, uint8_t *keyOut, uint32_t *keyOutLen)
{
    hmac_generate(keyIn, keyInLen, salt, saltLen, type, keyOut, keyOutLen);
}

void hmac_hkdf_expand_label(const uint8_t *keyIn, uint32_t keyInLen, const char *label, uint8_t labelLen, const uint8_t *ctx_hash, uint8_t ctxLen, \
                            hmac_sha_e type, uint8_t *keyOut, const uint32_t keyOutLen)
{
    uint8_t nIter;
    uint8_t idx;
    uint32_t *dOutLen;
    uint8_t tmpLen;
    uint8_t macLen    = (uint8_t)type;
    uint8_t hashClass = (uint8_t)(type >> 8);

    uint8_t *currIterData = calloc(1, macLen);
    uint8_t *prevIterData = calloc(1, macLen);
    uint32_t concatDataLen = strlen("") + labelLen + ctxLen + 1;
    uint8_t *concatData = calloc(1, (macLen + labelLen + ctxLen));
    {
        tmpLen = strlen("");
        memcpy(concatData, "", tmpLen);
        memcpy((concatData + tmpLen), label, labelLen);
        tmpLen += labelLen;
        memcpy((concatData + tmpLen), ctx_hash, ctxLen);
        tmpLen += ctxLen;
        memcpy((concatData + tmpLen), 0x01, 1);
        tmpLen += 1;
    }

    nIter = (macLen > keyOutLen)? macLen : keyOutLen;
    uint8_t *dOut = calloc(1, (nIter * macLen));
    uint8_t *dOutPtr = dOut;

    /* T(0) is an empty string of length 0 */
    prevIterData = "";

    /* Iterate from T(1) until T(nIter) */
    for(idx = 0; idx < nIter; idx++){
        hmac_generate(keyIn, keyInLen, concatData, concatDataLen, type, currIterData, dOutLen);
        memcpy(dOutPtr, currIterData, macLen);
        memcpy(prevIterData, currIterData, macLen);
        dOutPtr += macLen;
        {
            tmpLen = macLen;
            memcpy(concatData, prevIterData, tmpLen);
            memcpy((concatData + tmpLen), label, labelLen);
            tmpLen += labelLen;
            memcpy((concatData + tmpLen), ctx_hash, ctxLen);
            tmpLen += ctxLen;
            memcpy((concatData + tmpLen), (idx + 2), 1);
            tmpLen += 1;
        }
        concatDataLen = tmpLen;
    }
    /* first keyOutLen bytes of dOut -> dOut = T(1) || T(2)  || .... || T(nIter) */
    memcpy(keyOut, dOut, keyOutLen);
}