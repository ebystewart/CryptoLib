#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tls13.h"
#include "tls13_sm.h"
#include "math.h"
#include "rand.h"

typedef struct tls13_ctxDatabase_ tls13_ctxDatabase_t;

struct tls13_ctxDatabase_
{
    uint8_t ctxId;
    tls13_context_t *ctx;
    tls13_ctxDatabase_t *prev;
    tls13_ctxDatabase_t *next;
};

static tls13_ctxDatabase_t *ctxHead = NULL;

tls13_cipherSuiteData_t cipherSuiteData[] = {
    0x1302, /* assigned value for TLS_AES_256_GCM_SHA384 */
    0x1303, /* assigned value for TLS_CHACHA20_POLY1305_SHA256 */
    0x1301, /* assigned value for TLS_AES_128_GCM_SHA256 */
    0x00ff, /* assigned value for TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
};

uint8_t compressionMethodData[] = {
    0x00,
};

uint8_t ecPointsData[] = {
    0x00, /* assigned value for format "uncompressed" */
    0x01, /* assigned value for format "ansiX962_compressed_prime" */
    0x02, /* assigned value for format "ansiX962_compressed_char2" */
};

char hostnameData[] = "example.ulfheim.net";

uint16_t supportedGrpData[] = {
    0x001d, /* assigned value for the curve "x25519"    */
    0x0017, /* assigned value for the curve "secp256r1" */
    0x001e, /* assigned value for the curve "x448"      */
    0x0019, /* assigned value for the curve "secp521r1" */
    0x0018, /* assigned value for the curve "secp384r1" */
    0x0100, /* assigned value for the curve "ffdhe2048" */
    0x0101, /* assigned value for the curve "ffdhe3072" */
    0x0102, /* assigned value for the curve "ffdhe4096" */
    0x0103, /* assigned value for the curve "ffdhe6144" */
    0x0104, /* assigned value for the curve "ffdhe8192" */
};

uint16_t signAlgosData[] = {
    0x0403, /* assigned value for ECDSA-SECP256r1-SHA256 */
    0x0503, /* assigned value for ECDSA-SECP384r1-SHA384 */
    0x0603, /* assigned value for ECDSA-SECP521r1-SHA512 */
    0x0807, /* assigned value for ED25519 */
    0x0808, /* assigned value for ED448 */
    0x0809, /* assigned value for RSA-PSS-PSS-SHA256 */
    0x080a, /* assigned value for RSA-PSS-PSS-SHA384 */
    0x080b, /* assigned value for RSA-PSS-PSS-SHA512 */
    0x0804, /* assigned value for RSA-PSS-RSAE-SHA256 */
    0x0805, /* assigned value for RSA-PSS-RSAE-SHA384 */
    0x0806, /* assigned value for RSA-PSS-RSAE-SHA512 */
    0x0401, /* assigned value for RSA-PKCS1-SHA256 */
    0x0501, /* assigned value for RSA-PKCS1-SHA384 */
    0x0601, /* assigned value for RSA-PKCS1-SHA512 */
};

uint16_t supportedVersionsData[] = {
    0x0304, /* assigned value for TLS 1.3 */
};
uint8_t keyXchangeModesData[] = {
    0x01, /* assigned value for "PSK with (EC)DHE key establishment" */
};

const tls13_capability_t clientCapability = {
    .cipherSuiteLen         = 0x0008,
    .cipherSuiteList        = cipherSuiteData,
    .compressionMethodLen   = 0x01,
    .compressionMethodList  = compressionMethodData,
    .hostnameLen            = 0x13,
    .hostname               = hostnameData,
    .ecFormatsLen           = 0x03,
    .ecPoints               = ecPointsData,
    .supportedGrpLen        = 0x14,
    .supportedGrp           = supportedGrpData,
    .sessTktLen             = 0x00,
    .sessTkt                = NULL,
    .eTMLen                 = 0x00,
    .eTM                    = NULL,
    .extMasterSecretLen     = 0x00,
    .extMasterSecret        = NULL,
    .signAlgoLen            = 0x1C,
    .signAlgos              = signAlgosData,
    .supportedVersionLen    = 0x02,
    .supportedVersions      = supportedVersionsData,
    .keyXchangeModesLen     = 0x01,
    .keyXchangeModes        = keyXchangeModesData
};

static void tls13_cxt_queueInit(void);

static void tls13_cxt_queueInsert(tls13_context_t *ctx);

static void tls13_cxt_queueDelete(tls13_context_t *ctx);

static void tls13_ctx_queue(tls13_context_t *ctx, tls13_ctxOperation_e op);

static void tls13_cxt_queueInit(void)
{
    ctxHead = calloc(1, sizeof(tls13_ctxDatabase_t));
    ctxHead->ctxId = 0; /* 0 is the Id of the head node */
    ctxHead->next = NULL;
    ctxHead->prev = NULL;
}

static void tls13_cxt_queueInsert(tls13_context_t *ctx)
{

}

static void tls13_cxt_queueDelete(tls13_context_t *ctx)
{

}

static void tls13_ctx_queue(tls13_context_t *ctx, tls13_ctxOperation_e op)
{
    /* Do context queu management here */
    if (op == TLS13_CTX_ENQUEUE)
    {
    }
    else if (op == TLS13_CTX_DEQUEUE)
    {
    }
    else
    {
        assert(0);
    }
}

void tls13_init(tls13_context_t *ctx)
{
    tls13_ctx_queue(ctx, TLS13_CTX_ENQUEUE);

    if (ctx->role == TLS13_CLIENT)
    {
        /* Perform client handshake */
        // generate_random()
    }
    else if (ctx->role == TLS13_SERVER)
    {
        /* perform server handshake */
    }
    else
    {
        assert(0);
    }
}

void tls13_close(tls13_context_t *ctx)
{
    if (ctx->role == TLS13_CLIENT)
    {
    }
    else if (ctx->role == TLS13_SERVER)
    {
    }
    else
    {
        assert(0);
    }

    tls13_ctx_queue(ctx, TLS13_CTX_DEQUEUE);
}

void tls13_stateManager(tls13_context_t *ctx)
{
}