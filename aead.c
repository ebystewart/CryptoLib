#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"

/*
Encryption Steps
1. Key & Nonce Setup: Use a 256-bit key and a 96-bit nonce (or 192-bit for XChaCha20).
2. ChaCha20 Encryption: Encrypt the plaintext using ChaCha20 to generate a keystream, then XOR with the plaintext to get ciphertext (C).
3. Poly1305 Key Generation: Derive a Poly1305 key from the ChaCha20 key and nonce.
4. Message Construction for MAC: Concatenate:
    - Associated Data (AD).
    - Padding to align to 16 bytes.
    - Ciphertext (C).
    - Padding to align to 16 bytes.
    - Length of AD (64-bit little-endian).
    - Length of Ciphertext (64-bit little-endian).
5. Poly1305 Authentication: Run the constructed message through Poly1305 with the derived key to produce a 128-bit authentication tag (T).
6. Output: Send (Ciphertext + Tag) to the recipient. 
Ref: https://en.wikipedia.org/wiki/ChaCha20-Poly1305
*/
void aead_authenticate(aead_context_t *ctx, aead_suite_e cs)
{
    uint16_t counter = 0;
    uint16_t totalCount = 0;
    /* some sanity checks */
    if(cs == AEAD_CHACHA20_POLY1305){
        assert(ctx->keyLen == 256);
        assert(ctx->nonce == 96);
    }
    else if (cs == AEAD_XCHACHA20_POLY1305){
        assert(ctx->keyLen == 256);
        assert(ctx->nonce == 192);
    }
    totalCount = (ctx->plainTextLen - ctx->associatedDataLen)/64;
    uint16_t nonceInBytes = ceil((ctx->nonceLen / 8));
    uint8_t *oneTimeKey = calloc(1, 32);
    poly1305_mac_generate(ctx->nonce, nonceInBytes, ctx->key, ctx->keyLen, oneTimeKey);
    
    chacha20_encrypt_stream((ctx->plainText + ctx->associatedDataLen), (ctx->plainTextLen - ctx->associatedDataLen), ctx->key, \
                              ctx->nonce, ctx->cipherText, &ctx->cipherTextLen);

    uint16_t associatedDataPaddingLen = 0;
    if((ctx->associatedDataLen % 16) > 0){
        associatedDataPaddingLen = 16 - (ctx->associatedDataLen % 16);
    }
    uint16_t cipherTextPaddingLen = 0;
    if((ctx->cipherTextLen % 16) > 0){
        cipherTextPaddingLen = 16 - (ctx->cipherTextLen % 16);
    }
    uint16_t messageConstructLen = ctx->associatedDataLen + associatedDataPaddingLen + ctx->cipherTextLen + cipherTextPaddingLen + 8 + 8;
    uint8_t *messageConstruct = calloc(1, messageConstructLen);
    uint8_t *tmpMsgConstruct = messageConstruct;
    {
        memcpy(tmpMsgConstruct, ctx->cipherText, ctx->associatedDataLen);
        tmpMsgConstruct += ctx->associatedDataLen;
        memset(tmpMsgConstruct, 0x00, associatedDataPaddingLen);
        tmpMsgConstruct += associatedDataPaddingLen;
        memcpy(tmpMsgConstruct, ctx->cipherText, ctx->cipherTextLen);
        tmpMsgConstruct += ctx->cipherTextLen;
        memset(tmpMsgConstruct, 0x00, cipherTextPaddingLen);
        tmpMsgConstruct += (cipherTextPaddingLen + 6);
        memcpy(tmpMsgConstruct, (uint8_t *)&ctx->associatedDataLen, sizeof(uint16_t));
        tmpMsgConstruct += 8;
        memcpy(tmpMsgConstruct, (uint8_t *)&ctx->cipherTextLen, sizeof(uint16_t));
    }
    poly1305_mac_generate(messageConstruct, messageConstructLen, oneTimeKey, 32, ctx->authTag);
    ctx->authTagLen = 16;

    free(oneTimeKey);
    free(messageConstruct);
}
/*
1. Inputs: Receive (Ciphertext + Tag) and the original Key, Nonce, and AD.
2. Poly1305 Key & Message Setup: Same as encryption steps 3 & 4.
3. Poly1305 Verification: Generate a tag (T') from the inputs.
4. Compare Tags: Compare the received Tag (T) with the calculated T'. If they don't match, discard the data; it's tampered or invalid.
5. ChaCha20 Decryption: If tags match, use the Key and Nonce with ChaCha20 to decrypt the Ciphertext (C) back to the original plaintext. 
*/
bool aead_verify(aead_context_t *ctx, aead_suite_e cs)
{

}
