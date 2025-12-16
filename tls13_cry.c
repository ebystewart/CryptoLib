#include "tls13_cry.h"
#include "tls13_extensions.h"
#include "tls13_sm.h"
#include "tls13.h"
#include "aes.h"
#include "sha.h"
#include "aead.h"

/* function definitions */

bool tls13_verify_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, const uint8_t *mac, const uint16_t macLen, crypt_ctx_t *ctx)
{
    uint8_t tmpMac = calloc(1, macLen);
    tls13_generate_authTag(cipherText, cipherTextLen, tmpMac, macLen, ctx);
    int retVal = memcmp(tmpMac, mac, macLen);
    if (retVal == 0)
        return true;
    return false;
}

bool tls13_generate_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *mac, uint16_t macLen, crypt_ctx_t *ctx)
{
    //memset(mac, 0xFB, macLen);
    if(ctx->role == TLS13_CLIENT || ctx->role == TLS13_SERVER)
    {
        if(ctx->cipherSuite == TLS13_AES_128_GCM_SHA256)
        {
            sha2_compute_hash(cipherText, cipherTextLen, SHA_256, mac);
        }
        else if (ctx->cipherSuite == TLS13_AES_256_GCM_SHA384){
            sha3_compute_hash(cipherText, cipherTextLen, SHA3_384, mac);
        }
        else if (ctx->cipherSuite == TLS13_CHACHA20_POLY1305_SHA256){
            /* To be updated */
            //sha2_compute_hash(cipherText, cipherTextLen, SHA_256, mac);
            aead_context_t aead;
            aead.cipherText = cipherText; // should be plain text
            aead.cipherTextLen = cipherTextLen; // should be plain text length 
            aead.associatedDataLen = TLS13_RECORD_HEADER_SIZE;
            aead.key = ctx->handshakeKey;
            aead.keyLen = ctx->handshakeKeyLen;
            aead.nonce = ctx->handshakeIV;
            aead.nonceLen = ctx->handshakeIVLen;
            aead_authenticate(&ctx, AEAD_CHACHA20_POLY1305);
        }
    }
}

void tls13_encrypt(const uint8_t *plainText, const uint16_t plainTextLen, uint8_t *cipherText, crypt_ctx_t *ctx)
{
    //memcpy(cipherText, plainText, plainTextLen);
    if(ctx->role == TLS13_CLIENT || ctx->role == TLS13_SERVER)
    {
        if(ctx->cipherSuite == TLS13_AES_128_GCM_SHA256 || ctx->cipherSuite == TLS13_AES_256_GCM_SHA384)
        {
            aes_encrypt(AES_GCM, ctx->handshakeIV, plainText, cipherText, plainTextLen, ctx->handshakeKey, (ctx->handshakeKeyLen * 8));
        }
        else if (ctx->cipherSuite == TLS13_CHACHA20_POLY1305_SHA256){
            /* To be updated */
        }
    }
}

void tls13_decrypt(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *plainText, crypt_ctx_t *ctx)
{
    //memcpy(plainText, cipherText, cipherTextLen);
     if(ctx->role == TLS13_CLIENT || ctx->role == TLS13_SERVER)
    {
        if(ctx->cipherSuite == TLS13_AES_128_GCM_SHA256 || ctx->cipherSuite == TLS13_AES_256_GCM_SHA384)
        {
            aes_decrypt(AES_GCM, ctx->handshakeIV, cipherText, plainText, cipherTextLen, ctx->handshakeKey, (ctx->handshakeKeyLen * 8));
        }
        else if (ctx->cipherSuite == TLS13_CHACHA20_POLY1305_SHA256){
            /* To be updated */
        }
    }
}
