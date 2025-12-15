#include "tls13_cry.h"
#include "tls13_extensions.h"
#include "tls13_sm.h"
#include "tls13.h"
#include "aes.h"

/* function definitions */

bool tls13_verify_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, const uint8_t *mac, const uint16_t macLen, crypt_ctx_t *ctx)
{
    return true;
}

bool tls13_generate_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *mac, uint16_t macLen, crypt_ctx_t *ctx)
{
    memset(mac, 0xFB, macLen);
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
