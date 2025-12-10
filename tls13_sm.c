#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "tls13.h"
#include "tls13_sm.h"
#include "math.h"
#include "rand.h"
#include "ecc.h"
#include "sha.h"

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
    .cipherSuiteLen = 0x0008,
    .cipherSuiteList = cipherSuiteData,
    .compressionMethodLen = 0x01,
    .compressionMethodList = compressionMethodData,
    .hostnameLen = 0x13,
    .hostname = hostnameData,
    .ecFormatsLen = 0x03,
    .ecPoints = ecPointsData,
    .supportedGrpLen = 0x14,
    .supportedGrp = supportedGrpData,
    .sessTktLen = 0x00,
    .sessTkt = NULL,
    .eTMLen = 0x00,
    .eTM = NULL,
    .extMasterSecretLen = 0x00,
    .extMasterSecret = NULL,
    .signAlgoLen = 0x1C,
    .signAlgos = signAlgosData,
    .supportedVersionLen = 0x02,
    .supportedVersions = supportedVersionsData,
    .keyXchangeModesLen = 0x01,
    .keyXchangeModes = keyXchangeModesData
};

const tls13_cipherSuite_e serverSupportedSuites[] = {
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    TLS13_EMPTY_RENEGOTIATION_INFO_SCSV
};

const tls13_signAlgos_e serverSupportedSignAlgms[] = {
    TLS13_SIGNALGOS_ECDSA_SECP256r1_SHA256,
    TLS13_SIGNALGOS_ECDSA_SECP384r1_SHA384,
    TLS13_SIGNALGOS_ECDSA_SECP521r1_SHA512,
    TLS13_SIGNALGOS_ED25519,
    TLS13_SIGNALGOS_ED448,
    TLS13_SIGNALGOS_RSA_PSS_PSS_SHA256,
    TLS13_SIGNALGOS_RSA_PSS_PSS_SHA384,
    TLS13_SIGNALGOS_RSA_PSS_PSS_SHA512,
    TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256,
    TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA384,
    TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA512,
    TLS13_SIGNALGOS_RSA_PKCS1_SHA256,
    TLS13_SIGNALGOS_RSA_PKCS1_SHA384,
    TLS13_SIGNALGOS_RSA_PKCS1_SHA512
};

static void tls13_cxt_queueInit(void);

static tls13_ctxDatabase_t *tls13_cxt_queueFind(tls13_context_t *ctx);

static void tls13_cxt_queueInsert(tls13_context_t *ctx);

static void tls13_cxt_queueDelete(tls13_context_t *ctx);

static void tls13_ctx_queue(tls13_context_t *ctx, tls13_ctxOperation_e op);

static void tls13_hash_and_sign(uint8_t *clientHelloRec, uint16_t clientHelloRecLen, \
                        uint8_t *serverHelloRec, uint16_t serverHelloRecLen, \
                        uint8_t *serverWrappedRec, uint16_t serverWrappedRecLen, \
                        uint8_t *clientRecExclFin, uint16_t clientRecExclFinLen, \
                        tls13_cipherSuite_e cipherSuite, uint8_t *handshakeSign);

static tls13_cipherSuite_e tls13_selectCipherSuite(tls13_cipherSuite_e *cs, uint16_t csLen);
static tls13_signAlgos_e tls13_selectSignatureAlgo(tls13_signAlgos_e *sAlg, uint16_t sAlgLen);
static tls13_cipherSuite_e tls13_getCipherSuite(const tls13_context_t *ctx);
static tls13_signAlgos_e tls13_getSignatureType(const tls13_context_t *ctx);
static int tls13_getFileSize(const char *filepath);

static void tls13_ctx_queueDestroy(void)
{
    free(ctxHead);
}

static void tls13_ctx_queueInit(void)
{
    ctxHead = calloc(1, sizeof(tls13_ctxDatabase_t));
    ctxHead->ctxId = 0; /* 0 is the Id of the head node */
    ctxHead->next = NULL;
    ctxHead->prev = NULL;
}

static tls13_ctxDatabase_t *tls13_cxt_queueFind(tls13_context_t *ctx)
{
    tls13_ctxDatabase_t *ctxTmp = ctxHead;
    /* Exclude the head */
    ctxTmp = ctxTmp->next;
    while (memcmp(ctxTmp->ctx, ctx, sizeof(tls13_context_t)))
    {
        ctxTmp = ctxTmp->next;
        if (ctxTmp == NULL)
        {
            return NULL;
        }
    }
    return ctxTmp;
}

static void tls13_cxt_queueInsert(tls13_context_t *ctx)
{
    tls13_ctxDatabase_t *ctxTmp = ctxHead;
    /* Exclude the head */
    if(ctxTmp != NULL)
        ctxTmp = ctxTmp->next;

    while (ctxTmp != NULL && ctxTmp->next != NULL)
    {
        ctxTmp = ctxTmp->next;
    }
    if (ctxTmp != NULL)
    {
        ctxTmp->next = calloc(1, sizeof(tls13_ctxDatabase_t));
        ctxTmp = ctxTmp->next;
        ctxTmp->ctxId = ctxTmp->prev->ctxId + 1;
        ctxTmp->ctx->instanceId = ctxTmp->ctxId;
        memcpy(ctxTmp->ctx, ctx, sizeof(tls13_context_t));
        ctxTmp->next = NULL;
    }
}

static void tls13_cxt_queueDelete(tls13_context_t *ctx)
{
    tls13_ctxDatabase_t *ctxTmp = tls13_cxt_queueFind(ctx);

    if (ctxTmp != NULL)
    {
        ctxTmp = ctxTmp->prev;
        free(ctxTmp->next->ctx->client_random);
        free(ctxTmp->next->ctx->client_sessionId);
        free(ctxTmp->next->ctx->client_publicKey);
        free(ctxTmp->next);
        ctxTmp->next = NULL;
    }
}

static void tls13_ctx_queue(tls13_context_t *ctx, tls13_ctxOperation_e op)
{
    /* Do context queu management here */
    if (op == TLS13_CTX_ENQUEUE)
    {
        /* Insert the context to the database */
        tls13_cxt_queueInsert(ctx);
        if (ctx->role == TLS13_CLIENT)
        {
            /* Generate the 32-Byte client random (private key) for handshake */
            ctx->client_random = calloc(1, TLS13_RANDOM_LEN);
            ctx->client_publicKey = calloc(1, TLS13_RANDOM_LEN);
            //generate_random(ctx->client_random, TLS13_RANDOM_LEN);

            /* Generate a session Id - THis is unused in TLS 1.3 
               For session resume, pre-shared keys are used 
               Here, we generate for compatibility with TLS 1.2 */
            ctx->client_sessionId = calloc(1, TLS13_SESSION_ID_LEN);
            generate_random(ctx->client_sessionId, TLS13_SESSION_ID_LEN);

            ecc_point_t ecc_x25519;
            ecc_keypair_t keyPair;
            keyPair.privKey = ctx->client_random;
            keyPair.pubKey = ctx->client_publicKey;
            keyPair.privKeyLen = TLS13_RANDOM_LEN;

            /* Generate the public key */
            ecc_generate_keypair(&ecc_x25519, &keyPair);
        }
        else if (ctx->role == TLS13_SERVER){
            /* Generate the 32-Byte client random (private key) for handshake */
            ctx->server_random = calloc(1, TLS13_RANDOM_LEN);
            ctx->server_publicKey = calloc(1, TLS13_RANDOM_LEN);
            //generate_random(ctx->server_random, TLS13_RANDOM_LEN);

            /* Generate a session Id - THis is unused in TLS 1.3 
               For session resume, pre-shared keys are used 
               Here, we generate for compatibility with TLS 1.2 */
            ctx->server_sessionId = calloc(1, TLS13_SESSION_ID_LEN);
            generate_random(ctx->server_sessionId, TLS13_SESSION_ID_LEN);

            ecc_point_t ecc_x25519;
            ecc_keypair_t keyPair;
            keyPair.privKey = ctx->server_random;
            keyPair.pubKey = ctx->server_publicKey;
            keyPair.privKeyLen = TLS13_RANDOM_LEN;

            /* Generate the public key */
            ecc_generate_keypair(&ecc_x25519, &keyPair);
        }
        else{
            assert(0);
        }
        ctx->handshakeCompleted = false;
        ctx->handshakeExpired = false;
    }
    else if (op == TLS13_CTX_DEQUEUE)
    {
        /* Delete the context from the database */
        tls13_cxt_queueDelete(ctx);
    }
    else
    {
        assert(0);
    }
}

static int tls13_getFileSize(const char *filepath)
{
    FILE *fp = NULL;
    int size;

    fp = fopen(filepath, "rb");
    if(fp == NULL){
        perror("File couldn't be opened");
        return -1;
    }
    /* Seek to the end of the file */
    if(fseek(fp, 0, SEEK_END) != 0){
        perror("Couldn't seek over the file");
        fclose(fp);
        return -1;
    }
    size = ftell(fp);
    if(size == -1)
        perror("Couldn't get the seek location");

    fclose(fp);
    return size;
}

/* Initialize all teh context elements except for key-pair */
static tls13_init_ctx(tls13_context_t *ctx)
{
    ctx->server_random            = calloc(1, TLS13_RANDOM_LEN);
    ctx->server_sessionId         = calloc(1, TLS13_SESSION_ID_LEN);
    ctx->client_random            = calloc(1, TLS13_RANDOM_LEN);
    ctx->client_sessionId         = calloc(1, TLS13_SESSION_ID_LEN);

    if(ctx->role == TLS13_CLIENT){
        generate_random(ctx->client_random, TLS13_RANDOM_LEN);
        generate_random(ctx->client_sessionId, TLS13_SESSION_ID_LEN);
        //ctx->server_hostname          = calloc(1, 64); // tentative size
        //ctx->server_hostname_len      = 0;
    }
    else if (ctx->role == TLS13_SERVER){
        generate_random(ctx->server_random, TLS13_RANDOM_LEN);
        generate_random(ctx->server_sessionId, TLS13_SESSION_ID_LEN);
        //ctx->server_hostname          = NULL;//calloc(1, 64); // actual hostname shoudl come from app
        ctx->server_hostname_len      = 0;
    }
    ctx->server_publicKey         = calloc(1, TLS13_RANDOM_LEN);
    ctx->server_privateKey        = calloc(1, TLS13_RANDOM_LEN);
    ctx->client_publicKey         = calloc(1, TLS13_RANDOM_LEN);
    ctx->client_privateKey        = calloc(1, TLS13_RANDOM_LEN);
    ctx->sharedSecret             = calloc(1, TLS13_RANDOM_LEN);

    ctx->clientCapability         = calloc(1, sizeof(clientCapability)); // need to revisit the size
    ctx->clientCapabilityLen      = sizeof(clientCapability);
    {
        ctx->clientCapability->cipherSuiteList       = calloc(1, sizeof(clientCapability.cipherSuiteList));
        ctx->clientCapability->compressionMethodList = calloc(1, sizeof(clientCapability.compressionMethodList));
        ctx->clientCapability->hostname              = calloc(1, 32);
        ctx->clientCapability->ecPoints              = calloc(1, sizeof(clientCapability.ecPoints));
        ctx->clientCapability->supportedGrp          = calloc(1, sizeof(clientCapability.supportedGrp));
        ctx->clientCapability->sessTkt               = calloc(1, sizeof(clientCapability.sessTkt));
        ctx->clientCapability->eTM                   = calloc(1, sizeof(clientCapability.eTM)); /* Encrypt-then-MAC */
        ctx->clientCapability->extMasterSecret       = calloc(1, sizeof(clientCapability.extMasterSecret));
        ctx->clientCapability->signAlgos             = calloc(1, sizeof(clientCapability.signAlgos));
        ctx->clientCapability->supportedVersions     = calloc(1, sizeof(clientCapability.supportedVersions));
        ctx->clientCapability->keyXchangeModes       = calloc(1, sizeof(clientCapability.keyXchangeModes));
    }
    ctx->serverExtension          = calloc(1, 50); //tentative size
    ctx->serverExtensionLen       = 0;   
    if(ctx->role == TLS13_CLIENT)
    {
        ctx->certfd = open("certs/client.der", O_RDONLY);
        ctx->clientCertLen = tls13_getFileSize("certs/client.der");
        read(ctx->certfd, ctx->clientCert, ctx->clientCertLen); //error handling
        close(ctx->certfd);
    }
    else{
        ctx->clientCert               = calloc(1, 1536); // need to give address of certificate file
        ctx->clientCertLen            = 0; // need to revisit        
    }
    ctx->clientCertVerify         = calloc(1, 512); // need to revisit
    ctx->clientCertVerifyLen      = 0;
    if (ctx->role == TLS13_SERVER)
    {
        ctx->serverCertLen = tls13_getFileSize("certs/server.der");
        ctx->serverCert               = calloc(1, ctx->serverCertLen);
        ctx->certfd = open("certs/server.der", O_RDONLY);
        read(ctx->certfd, ctx->serverCert, ctx->serverCertLen); //error handling
        close(ctx->certfd);
    }
    else{
        ctx->serverCert               = calloc(1, 1536); // need to give address of certificate file
        ctx->serverCertLen            = 0; // need to revisit   
    }

    ctx->serverCertVerify         = calloc(1, 512);
    ctx->serverCertVerifyLen      = 0;
    ctx->clientHandshakeSignature = calloc(1, 512);
    ctx->clientHandshakeSignLen   = 0;
    ctx->serverHandshakeSignature = calloc(1, 512);
    ctx->serverHandshakeSignLen   = 0; 

    ctx->clientHandshakeKey    = calloc(1, TLS13_KEY_SIZE);
    ctx->clientHandshakeKeyLen = TLS13_KEY_SIZE;
    ctx->clientHandshakeIV     = calloc(1, 12);
    ctx->clientHandshakeIVLen  = 12;
    ctx->serverHandshakeKey    = calloc(1, TLS13_KEY_SIZE);
    ctx->serverHandshakeKeyLen = TLS13_KEY_SIZE;
    ctx->serverHandshakeIV     = calloc(1, 12);
    ctx->serverHandshakeIVLen  = 12;
}

static tls13_deInit_ctx(tls13_context_t *ctx)
{
    memset(ctx->client_random, 0, TLS13_RANDOM_LEN);
    memset(ctx->server_random, 0, TLS13_RANDOM_LEN);
    memset(ctx->client_sessionId, 0, TLS13_SESSION_ID_LEN);
    memset(ctx->server_sessionId, 0, TLS13_SESSION_ID_LEN);
    memset(ctx->clientHandshakeKey, 0, ctx->clientHandshakeKeyLen);
    memset(ctx->clientHandshakeIV, 0, ctx->clientHandshakeIVLen);
    memset(ctx->serverHandshakeKey, 0, ctx->serverHandshakeKeyLen);
    memset(ctx->serverHandshakeIV, 0, ctx->serverHandshakeIVLen);
    memset(ctx->serverCert, 0, ctx->serverCertLen);
    //close(ctx->servedCertfd);

    free(ctx->client_random);
    free(ctx->server_random);
    free(ctx->client_sessionId);
    free(ctx->server_sessionId);
    //free(ctx->server_hostname);
    free(ctx->client_publicKey);
    free(ctx->server_publicKey);
    free(ctx->clientCapability);
    free(ctx->serverExtension);
    free(ctx->clientCert);
    free(ctx->clientCertVerify);
    free(ctx->serverCert);
    free(ctx->serverCertVerify);
    free(ctx->clientHandshakeSignature);
    free(ctx->serverHandshakeSignature);

    free(ctx->clientHandshakeKey);
    free(ctx->clientHandshakeIV);
    free(ctx->serverHandshakeKey);
    free(ctx->serverHandshakeIV);

    /* Set all pointers to NULL, to detect Use-after-free scenario */
    ctx->client_random            = NULL;
    ctx->server_random            = NULL;
    ctx->client_sessionId         = NULL;
    ctx->server_sessionId         = NULL;
    //ctx->server_hostname          = NULL;
    ctx->client_publicKey         = NULL;
    ctx->server_publicKey         = NULL;
    ctx->clientCapability         = NULL;
    ctx->serverExtension          = NULL;
    ctx->clientCert               = NULL;
    ctx->clientCertVerify         = NULL;
    ctx->serverCert               = NULL;
    ctx->serverCertVerify         = NULL;
    ctx->clientHandshakeSignature = NULL;
    ctx->serverHandshakeSignature = NULL;

    ctx->clientHandshakeKey   = NULL;
    ctx->clientHandshakeIV    = NULL;
    ctx->serverHandshakeKey   = NULL;
    ctx->serverHandshakeIV    = NULL;
}

static tls13_check_ctx(tls13_context_t *ctx)
{
    assert(ctx->role == TLS13_CLIENT || ctx->role == TLS13_SERVER);
    /* Both client and server needs client and server socket details to send data */

    if(ctx->role == TLS13_CLIENT){
        assert(ctx->client_ip != 0);
        assert(ctx->client_port != 0);
        assert(ctx->server_hostname_len > 0);
    }
    else if (ctx->role == TLS13_SERVER){
        assert(ctx->server_ip != 0);
        assert(ctx->server_port != 0);
    }
    else{
        /* Do Nothing */
    }
} 

static uint16_t portNum = 27000;
static uint16_t tls13_getNextPortNumber(void)
{
    return (portNum + 4);
}

static uint32_t tls13_getIPAddress(void)
{
    return 0;
}

//tricky one
static size_t tls13_getWrappedRecPktLength(uint8_t *tls_pkt){

    size_t length;
    uint8_t idx = 0;
    uint16_t recordLen = 0;

    tls13_recordHdr_t *rHdr = calloc(1, sizeof(tls13_recordHdr_t));
    memcpy(rHdr, tls_pkt, sizeof(tls13_recordHdr_t));
    recordLen = tls13_ntohs(rHdr->recordLen);
    if(recordLen != 0)
    {
        if(rHdr->recordType == TLS13_CHANGE_CIPHERSPEC_RECORD || rHdr->recordType == TLS13_APPDATA_RECORD){
            recordLen = rHdr->recordLen;
            if(recordLen != 0)
                length = recordLen + TLS13_RECORD_HEADER_SIZE;
        }
        else{
            recordLen = 0;
            return length;
        }
        //rHdr += length;
    }
    free(rHdr);

    return length;
}

/* The handshake keys are claculated from public and private keys of client and server
   along with the hash of server hello and client hello messages */
static void tls13_computeHandshakeKeys(tls13_context_t *ctx, const uint8_t *clientHello_pkt, const uint16_t clientHelloLen, \
                                      const uint8_t *serverHello_pkt, const uint16_t serverHelloLen)
{
    size_t helloLen = 0;
    if(!clientHello_pkt && !serverHello_pkt){
        helloLen = clientHelloLen + serverHelloLen - TLS13_RECORD_HEADER_SIZE - TLS13_RECORD_HEADER_SIZE;
        uint8_t *message = calloc(1, helloLen);
        memcpy(message, (clientHello_pkt + TLS13_RECORD_HEADER_SIZE), (clientHelloLen - TLS13_RECORD_HEADER_SIZE));
        memcpy((message + clientHelloLen), (serverHello_pkt + TLS13_RECORD_HEADER_SIZE), (serverHelloLen - TLS13_RECORD_HEADER_SIZE));

        if(ctx->serverCipherSuiteSupported == TLS13_AES_256_GCM_SHA384){

            uint8_t *digest = calloc(1, 384);
            sha3_compute_hash(message, helloLen, SHA3_384, digest);
            #ifndef DEBUG
            printf("The sha-384 hash of server and client hello excluding the record header is:\n");
            for(int i=0; i < helloLen; i++){
                printf("[%d]: %x\n", i, digest[i]);
            }
            printf("\n");
            #endif
            /* extract the shared secret */
            if(ctx->role == TLS13_CLIENT){
                ecc_extract_secret(ctx->server_publicKey, ctx->client_privateKey, ctx->keyLen, 486662, ctx->sharedSecret);
            }
            else if (ctx->role == TLS13_SERVER){
                ecc_extract_secret(ctx->client_publicKey, ctx->server_privateKey, ctx->keyLen, 486662, ctx->sharedSecret);
            }
            /* Employ a series of key Derivation actions */
            free(digest);
        }
        else if(ctx->serverCipherSuiteSupported == TLS13_AES_128_GCM_SHA256 || ctx->serverCipherSuiteSupported == TLS13_CHACHA20_POLY1305_SHA256){
            uint8_t *digest = calloc(1, 256);
            sha256_compute_hash(message, helloLen, digest);
            #ifndef DEBUG
            printf("The sha-256 hash of server and client hello excluding the record header is:\n");
            for(int i=0; i < helloLen; i++){
                printf("[%d]: %x\n", i, digest[i]);
            }
            printf("\n");
            #endif
            /* logic to be implemented */
            
            free(digest);
        }
        else{
            free(message);
            assert(0);
        }
        free(message);
    }
}

static void tls13_hash_and_sign(uint8_t *clientHelloRec, uint16_t clientHelloRecLen, \
                        uint8_t *serverHelloRec, uint16_t serverHelloRecLen, \
                        uint8_t *serverWrappedRec, uint16_t serverWrappedRecLen, \
                        uint8_t *clientRecExclFin, uint16_t clientRecExclFinLen, \
                        tls13_cipherSuite_e cipherSuite, uint8_t *handshakeSign)
{

}

static void *__client_handshake_thread(void *arg)
{
    int opt = 1;
    bool serverHelloReceived = false;
    bool serverWrappedRecReceived = false;
    uint16_t handshakeSignLen;
    tls13_recordType_e first_record;
    size_t clientHelloLen = 0;
    size_t serverHelloLen = 0;
    size_t serverWrappedRecLen = 0;
    size_t clientWrappedRecLen = 0;
    uint8_t addr_len;
    tls13_context_t *ctx = (tls13_context_t *)arg;

    struct sockaddr_in server_addr;
    socklen_t addr_size = sizeof(server_addr);
    fd_set read_fds; // Set of file descriptors to monitor for reading
    FD_ZERO(&read_fds); // Clear the set
    FD_SET(ctx->client_fd, &read_fds); // Add a socket to the set

    struct timeval timeout;
    timeout.tv_sec = 10; // 5-second timeout
    timeout.tv_usec = 0;


    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    /* We need to keep the backup of all the messages for signature calculation for finished record */
    /* assuming the following messages:
     *  1. Client hello (sent)
     *  2. Server hello (received)
     *  3. Client Finished (this has the signature)
    */
    uint8_t *clientHello_pkt      = calloc(1, TLS13_CLIENT_HELLO_MAX_LEN);
    uint8_t *temp                 = calloc(1, TLS13_SERVER_WRAPPEDREC_MAX_LEN);
    uint8_t *serverHello_pkt      = calloc(1, TLS13_SERVER_HELLO_MAX_LEN); // If pkt is more than max size, we may receive as 2 pkts; need to handle this
    uint8_t *serverWrappedRec_pkt = calloc(1, TLS13_SERVER_WRAPPEDREC_MAX_LEN);
    uint8_t *clientFinish_pkt     = calloc(1, TLS13_CLIENT_FINISHED_MAX_LEN);

    /* Prepare the client hello pkt */
    tls13_prepareClientHello(ctx->client_random, ctx->client_sessionId, ctx->server_hostname, ctx->client_publicKey, ctx->keyLen, clientHello_pkt);

    /* Send the client hello pkt over TCP to the destined socket */
    clientHelloLen = (size_t)((((tls13_clientHello_t *)clientHello_pkt)->recordHeader.recordLen));
    clientHelloLen = tls13_ntohs(clientHelloLen) + TLS13_RECORD_HEADER_SIZE;
    
#ifdef DEBUG
    printf("Client Hello Length is %d\n", clientHelloLen);
    for (int i= 0; i < 260; i++){
        printf("%x\n", clientHello_pkt[i]);
    }
    printf("\n");
#endif
    int rc = send(ctx->client_fd, clientHello_pkt, clientHelloLen, 0);
    if(rc != clientHelloLen)
        perror("client Hello transmission error");
    else
        printf("client hello transmission succeeded\n");

    /* Wait for the server hello response to be received */
    while (serverHelloReceived == false)
    {
        pthread_testcancel();
        {        
            //printf("Client ready to receive server hello......\n");
            select(ctx->client_fd + 1, &read_fds, NULL, NULL, &timeout);

            /* recieve server hello first */
            if (FD_ISSET(ctx->client_fd, &read_fds))      
            {
                int rc = recvfrom(ctx->client_fd, temp, TLS13_SERVER_HELLO_MAX_LEN, 0, (struct sockaddr *)&server_addr, &addr_size);
                if(rc == -1)
                    perror("reception failed");
                else
                    printf("received data from server of length %d\n", rc);

                /* wait for the response to receive - Blocking call */
                //rc = recv(ctx->client_fd, temp, sizeof(temp), 0);// NULL, 0);
                first_record = temp[TLS13_RECORD_HEADER_OFFSET];
                if (temp[TLS13_HANDSHAKE_HEADER_OFFSET] == TLS13_HST_SERVER_HELLO && first_record == TLS13_HANDSHAKE_RECORD)
                {
                    memcpy(serverHello_pkt, temp, rc);
                    serverHelloLen = (size_t)(tls13_ntohs((((tls13_serverHello_t *)serverHello_pkt)->recordHeader.recordLen)) + TLS13_RECORD_HEADER_SIZE);
                    //assert(rc == serverHelloLen);
                    #ifndef DEBUG
                        printf("Received Server Hello Length is %d\n", serverHelloLen);
                        for (int i= 0; i < serverHelloLen; i++){
                            printf("[%d] %x\n", i, serverHello_pkt[i]);
                        }
                        printf("\n");
                    #endif
                    tls13_extractServerHello(ctx->server_random, ctx->client_sessionId, &ctx->serverCipherSuiteSupported, ctx->server_publicKey, \
                        &ctx->keyLen, &ctx->keyType, (tls13_serverExtensions_t *)ctx->serverExtension, &ctx->serverExtensionLen, serverHello_pkt);
                
                    tls13_computeHandshakeKeys(ctx, clientHello_pkt, clientHelloLen, serverHello_pkt, serverHelloLen);
                    serverHelloReceived = true;
                }
            }
        }
    }
    printf("Server hello received...\n");
    memset(temp, 0, TLS13_SERVER_WRAPPEDREC_MAX_LEN);
    FD_SET(ctx->client_fd, &read_fds); // Add a socket to the set
    while (serverWrappedRecReceived == false)
    {
        pthread_testcancel();
        {        
            //printf("Client ready to receive server wrapped record......\n");
            select(ctx->client_fd + 1, &read_fds, NULL, NULL, &timeout);

            /* recieve server wrapped record now */
            if (FD_ISSET(ctx->client_fd, &read_fds))      
            {
                int rc = recvfrom(ctx->client_fd, temp, TLS13_SERVER_WRAPPEDREC_MAX_LEN, 0, (struct sockaddr *)&server_addr, &addr_size);
                //int rc = recv(ctx->client_fd, serverWrappedRec_pkt, TLS13_SERVER_WRAPPEDREC_MAX_LEN, 0);
                if(rc == -1)
                    perror("socket reception failed");
                else
                    printf("received data from server of length %d\n", rc);
                serverWrappedRecLen = rc;
                first_record = temp[TLS13_RECORD_HEADER_OFFSET];
                if(first_record == TLS13_APPDATA_RECORD)
                {
                    memcpy(serverWrappedRec_pkt, temp, rc);
                    #ifndef DEBUG
                        printf("Received Server Wrapped Record Length is %d\n", rc);
                        for (int i= 0; i < rc; i++){
                            printf("[%d] %x\n", i, serverWrappedRec_pkt[i]);
                        }
                        printf("\n");
                    #endif

                    tls13_extractServerWrappedRecord(serverWrappedRec_pkt, ctx->serverCert, ctx->serverCertLen, ctx->serverHandshakeSignature, ctx->serverCertVerify, &ctx->serverCertVerifyLen, \
                                                     ctx->serverCipherSuiteSupported, ctx->signatureAlgoSupported);
                    serverWrappedRecReceived = true;
                }
            }
        }
    }
    print_context(ctx);
    /* Extract the hash length from the cipher suite supported 
       This will be helpful to compute the signature */
    if (ctx->serverCipherSuiteSupported == TLS13_AES_128_GCM_SHA256 || ctx->serverCipherSuiteSupported == TLS13_CHACHA20_POLY1305_SHA256){
        handshakeSignLen = 256U;
    }else if(ctx->serverCipherSuiteSupported == TLS13_AES_256_GCM_SHA384){
        handshakeSignLen = 384U;
    }
    else{
        /* assert error as unspoorted TLS 1.3 cupher suite is used */
        printf("Server cipher suite selected is %d\n", ctx->serverCipherSuiteSupported);
        assert(0);
    }

    uint8_t *handshakeSign = calloc(1, handshakeSignLen);

    /* At this point, we should be able to calculate the hash and sign it */
    tls13_hash_and_sign(clientHello_pkt, clientHelloLen,
                        serverHello_pkt, serverHelloLen,
                        serverWrappedRec_pkt, serverWrappedRecLen,
                        clientFinish_pkt, TLS13_CLIENT_FINISHED_LEN - handshakeSignLen, //should use an offset to exclude the handshake record completely
                        ctx->serverCipherSuiteSupported, handshakeSign);

    tls13_cipherSuite_e cs = tls13_getCipherSuite(ctx);
    /* Prepare the wrapped record (certificate, certificateVerify, finished)*/
    // need to handle if certificate and certverify also needs to be sent
#ifndef DEBUG
    ctx->clientCertVerifyLen = 256;
    ctx->clientHandshakeSignLen = 48;
    memset(ctx->clientCertVerify, 0xCA, 256);
    memset(ctx->clientHandshakeSignature, 0xFA, 48);
#endif
    clientWrappedRecLen = tls13_prepareClientWrappedRecord(ctx->clientHandshakeSignature, ctx->clientHandshakeSignLen, "hello", strlen("hello"), cs, clientFinish_pkt);
#ifndef DEBUG
    printf("Prepared client Wrapped Record Length is %d\n", clientWrappedRecLen);
    for (int i = 0; i < clientWrappedRecLen; i++)
    {
        printf("[%d] %x\n", i, clientFinish_pkt[i]);
    }
    printf("\n");
#endif
    /* check if the handshake is successful */
    // actually server handshake signature is calculated and compared with the received one
    if (0 != memcmp(ctx->clientHandshakeSignature, ctx->serverHandshakeSignature, ctx->clientHandshakeSignLen) && (ctx->serverHandshakeSignLen != 0)){
        tls13_alert_t alert;
        size_t alertLen;
        uint8_t *alert_pkt = calloc(1, TLS13_ALERT_LEN);
        {
            alert.level = TLS13_ALERT_FATAL;
            alert.description = TLS13_HANDSHAKE_FAILURE;
            alertLen = tls13_prepareAlertRecord(&alert, cs, alert_pkt);
            send(ctx->client_fd, alert_pkt, alertLen, 0);
            ctx->handshakeExpired = true;
        }
        free(alert_pkt);
        /* handshake failed - terminate the thread */
        pthread_exit(0);
    }
    else{
        send(ctx->client_fd, clientFinish_pkt, clientWrappedRecLen, 0);
        ctx->handshakeCompleted = true;
        ctx->handshakeExpired = false;
    }

    free(clientHello_pkt);
    free(temp);
    free(serverHello_pkt);
    free(serverWrappedRec_pkt);
    free(clientFinish_pkt);
    free(handshakeSign);

    /* This thread should terminated when the handshake is complete */
    pthread_exit(0);
}

static void *__server_handshake_thread(void *arg)
{
    int opt = 1;
    uint8_t addr_len;
    bool clientHelloReceived = false;
    bool clientFinishedReceived = false;
    tls13_context_t *ctx = (tls13_context_t *)arg;

    size_t clientHelloLen  = 0;
    size_t serverHelloLen = 0;
    size_t serverWrappedRecLen = 0;
    size_t clientFinishRecLen = 0;

    struct sockaddr_in client_addr;
    socklen_t addr_size = sizeof(client_addr);

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);  // joinable ??

    fd_set read_fds; // Set of file descriptors to monitor for reading
    FD_ZERO(&read_fds); // Clear the set

    struct timeval timeout;
    timeout.tv_sec = 10; // 5-second timeout
    timeout.tv_usec = 0;

    /* We need to keep the backup of all the messages for signature calculation for finished record */
    /* assuming the following messages:
     *  1. Client hello (received)
     *  2. Server hello (sent)
     *  3. Server Finished (this has the signature)
    */
    uint8_t *clientHello_pkt = calloc(1, TLS13_CLIENT_HELLO_MAX_LEN);
    uint8_t *serverHello_pkt = calloc(1, TLS13_SERVER_HELLO_MAX_LEN); // If pkt is more than max size, we may receive as 2 pkts; need to handle this
    uint8_t *serverWrappedRec_pkt = calloc(1, TLS13_SERVER_WRAPPEDREC_MAX_LEN);
    uint8_t *clientFinish_pkt     = calloc(1, TLS13_CLIENT_FINISHED_MAX_LEN);

    /* Blocking call to accept connection to server's designated socket */
    printf("waiting to accept connections ....\n");
    if((ctx->client_fd = accept(ctx->server_fd, (struct sockaddr *)&client_addr, &addr_size)) < 0){
        perror("Connection not accepted");
        exit(1);
    }
    else{
        ctx->client_ip = tls13_ntohl(client_addr.sin_addr.s_addr);
        ctx->client_port = tls13_ntohs(client_addr.sin_port);
        printf("Connection accepted with comm fd %d from client Ip %d and port %d\n", ctx->client_fd, ctx->client_ip, ctx->client_port);
    }

    FD_SET(ctx->client_fd, &read_fds); // Add a socket to the set
    while (clientHelloReceived == false)
    {
        printf("server handshake thread \n");
        pthread_testcancel();
        printf("Waiting for client hello message\n");
        
        select(ctx->client_fd + 1, &read_fds, NULL, NULL, &timeout);

        /* recieve client hello first */
        if (FD_ISSET(ctx->client_fd, &read_fds))      
        {
            //int rc = recv(ctx->client_fd, clientHello_pkt, TLS13_CLIENT_HELLO_MAX_LEN, 0);// (struct sockaddr *)&server_addr, &addr_len);
            int rc = recvfrom(ctx->client_fd, clientHello_pkt, TLS13_CLIENT_HELLO_MAX_LEN, 0, 
                                    (struct sockaddr *)&client_addr, &addr_size);
            if(rc == -1)
                perror("reception failed");
            else
               printf("Received Client Hello -> size (%d) \n", rc); 
#ifdef DEBUG
    //printf("Received Client Hello\n");
    for (int i= 0; i < 260; i++){
        printf("[%d] -> %x\n", i, clientHello_pkt[i]);
    }
    printf("\n");
#endif
            tls13_extractClientHello(ctx->client_random, ctx->client_sessionId, NULL, ctx->clientCapability, ctx->keyType, ctx->client_publicKey, ctx->keyLen, clientHello_pkt);
            fix_capability_endianess(ctx->clientCapability, ctx->clientCapabilityLen);
            ctx->signatureAlgoSupported = tls13_selectSignatureAlgo(ctx->clientCapability->signAlgos, ctx->clientCapability->signAlgoLen);
            #ifndef DEBUG
                print_capability(ctx->clientCapability, ctx->clientCapabilityLen);
            #endif
            tls13_computeHandshakeKeys(ctx, clientHello_pkt, clientHelloLen, serverHello_pkt, serverHelloLen);
            /* Receive the server hello and extract the data */
            clientHelloReceived = true;
        }
    }
    /* Choose cipher suite and signature algorithm from clients list based on priority */
    tls13_cipherSuite_e cs_supported = tls13_selectCipherSuite(ctx->clientCapability->cipherSuiteList, ctx->clientCapability->cipherSuiteLen);
    ctx->serverCipherSuiteSupported = cs_supported;
    tls13_signAlgos_e sigAlg_supported = tls13_selectSignatureAlgo(ctx->clientCapability->signAlgos, ctx->clientCapability->signAlgoLen);
    ctx->serverCipherSuiteSupported = sigAlg_supported;

    /* send server hello */
    serverHelloLen = tls13_prepareServerHello(ctx->server_random, ctx->server_sessionId, cs_supported, ctx->server_publicKey, ctx->keyLen, ctx->keyType, \
                              ctx->serverExtension, ctx->serverExtensionLen, serverHello_pkt);
    int rc = send(ctx->client_fd, serverHello_pkt, serverHelloLen, 0);
    assert(rc == serverHelloLen);
#ifndef DEBUG
    printf("Prepared Server Hello (size: %d)\n",serverHelloLen);
    for (int i = 0; i < serverHelloLen; i++){
        printf("[%d] -> %x\n", i, serverHello_pkt[i]);
    }
    printf("\n");
    ctx->serverCertVerifyLen = 256;
    ctx->serverHandshakeSignLen = 48;
    memset(ctx->serverCertVerify, 0xCA, 256);
    memset(ctx->serverHandshakeSignature, 0xFA, 48);
    printf("Server certificate Length is %d; cert signature length is %d; server handshake signature length is %d\n", ctx->serverCertLen, ctx->serverCertVerifyLen, ctx->serverHandshakeSignLen);
#endif

    serverWrappedRecLen = tls13_prepareServerWrappedRecord(ctx->serverCert, ctx->serverCertLen, ctx->serverCertVerify, ctx->serverCertVerifyLen, \
                                        ctx->serverHandshakeSignature, ctx->serverHandshakeSignLen, ctx->serverCipherSuiteSupported, \
                                        ctx->signatureAlgoSupported, serverWrappedRec_pkt);
    rc = send(ctx->client_fd, serverWrappedRec_pkt, serverWrappedRecLen, 0);
    //rc = sendto(ctx->client_fd, serverWrappedRec_pkt, serverWrappedRecLen, 0,(struct sockaddr *)&client_addr, &addr_len);
    assert(rc == serverWrappedRecLen);
#ifndef DEBUG
    printf("Prepared Server Wrapped record: size (%d)/sent bytes (%d)\n", serverWrappedRecLen, rc);
    for (int i = 0; i < serverWrappedRecLen; i++){
        printf("[%d] -> %x\n", i, serverWrappedRec_pkt[i]);
    }
    printf("\n");
#endif
    /* Receive client finished */
    FD_SET(ctx->client_fd, &read_fds); // Add a socket to the set
    while(clientFinishedReceived == false)
    {        
        select(ctx->client_fd + 1, &read_fds, NULL, NULL, &timeout);
        /* recieve client hello first */
        if (FD_ISSET(ctx->client_fd, &read_fds))      
        {
            //int rc = recv(ctx->client_fd, clientHello_pkt, TLS13_CLIENT_HELLO_MAX_LEN, 0);// (struct sockaddr *)&server_addr, &addr_len);
           clientFinishRecLen = recvfrom(ctx->client_fd, clientFinish_pkt, TLS13_CLIENT_FINISHED_MAX_LEN, 0, 
                                    (struct sockaddr *)&client_addr, &addr_len);
#ifndef DEBUG
    printf("Received Client Finish - size (%d)\n", clientFinishRecLen);
    for (int i= 0; i < clientFinishRecLen; i++){
        printf("[%d] -> %x\n", i, clientFinish_pkt[i]);
    }
    printf("\n");
#endif
            tls13_extractClientWrappedRecord(clientFinish_pkt, ctx->clientHandshakeSignature, ctx->clientHandshakeSignLen, \
                                             NULL, 0, cs_supported); //app data to be paassed to application
            clientFinishedReceived = true;
        }
    }
}

static void *__tls_transmit_thread(void *arg)
{
    tls13_context_t *ctx = (tls13_context_t *)arg;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    while (1)
    {
        pthread_testcancel();
    }
}

static void *__tls_receive_thread(void *arg)
{
    tls13_context_t *ctx = (tls13_context_t *)arg;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    while (1)
    {
        pthread_testcancel();
    }
}

static void tls13_startClientHandshakeThread(tls13_context_t *ctx)
{
    pthread_attr_t attr;
    pthread_t clientHandshake_thread;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&clientHandshake_thread, &attr, __client_handshake_thread, (void *)ctx))
    {
        printf("Client Handshake thread creation failed with error code %d\n", errno);
        exit(1); /* cancel point */
    }
}

static void tls13_startServerHandshakeThread(tls13_context_t *ctx)
{
    pthread_attr_t attr;
    pthread_t serverHandshake_thread;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&serverHandshake_thread, &attr, __server_handshake_thread, (void *)ctx))
    {
        printf("Client Handshake thread creation failed with error code %d\n", errno);
        exit(1); /* cancel point */
    }
}

static void tls13_startDataTransmitThread(tls13_context_t *ctx)
{
    pthread_attr_t attr;
    pthread_t dataTransmit_thread;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&dataTransmit_thread, &attr, __tls_transmit_thread, (void *)ctx))
    {
        printf("TLS 1.3 data Transmit thread creation failed with error code %d\n", errno);
        exit(0); /* cancel point */
    }
}

static void tls13_startDataReceiveThread(tls13_context_t *ctx)
{
    pthread_attr_t attr;
    pthread_t dataTransmit_thread;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(&dataTransmit_thread, &attr, __tls_receive_thread, (void *)ctx))
    {
        printf("TLS 1.3 data receive thread creation failed with error code %d\n", errno);
        exit(0); /* cancel point */
    }
}

static void init_clientSocket(tls13_context_t *ctx)
{
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(ctx->server_ip);//INADDR_ANY;//0x7F000001UL; //tls13_getIPAddress();
    server_addr.sin_port = htons(ctx->server_port);

    /* IP also needs to be updated */
    printf("Setting up the client socket connection......\n");
    ctx->client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // SOCK_DGRAM, IPPROTO_UDP);
    if(ctx->client_fd < 0){
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }
    printf("Client socket created with fd: %d\n", ctx->client_fd);

    if(connect(ctx->client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }
    printf("Client socket created\n");
}

static void init_serverSocket(tls13_context_t *ctx)
{
    int opt = 1;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(ctx->server_ip);
    server_addr.sin_port = htons(ctx->server_port);

    if((ctx->server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        perror("socket failed");
        exit(EXIT_FAILURE);
    } // SOCK_DGRAM, IPPROTO_UDP);

    if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0U)
    {
        printf("%s(): Setting of socket option to reuse address failed.\n", __FUNCTION__);
        exit(1);
    }
    if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEPORT, (char *)&opt, sizeof(opt)) < 0U)
    {
        printf("%s(): Setting of sock option to reuse port address failed\n", __FUNCTION__);
        exit(1);
    }

    /* IP also needs to be updated */
    if (bind(ctx->server_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("socket bind failed for instance %d\n", ctx->instanceId);
        exit(1);
    }
    printf("Server socket creation successful... Listening for new connections from client...\n");

    if(listen(ctx->server_fd, 3) < 0){
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
}

void tls13_init(tls13_context_t *ctx)
{
    if(!ctxHead)
        tls13_ctx_queueInit();
        
    /* create the context entry in database */
    tls13_check_ctx(ctx);
    tls13_ctx_queue(ctx, TLS13_CTX_ENQUEUE);
    tls13_init_ctx(ctx);

    if (ctx->role == TLS13_CLIENT)
    {
        assert(ctx->client_ip > 0);
        assert(ctx->client_port > 0);
        /* Create and bind a socket */
        init_clientSocket(ctx);
        /* Start the client handshake process */
        tls13_startClientHandshakeThread(ctx);
    }
    else if (ctx->role == TLS13_SERVER)
    {
        assert(ctx->server_ip > 0);
        assert(ctx->server_port > 0);
        /* Create and bind a socket */
        init_serverSocket(ctx);
        /* Start the server handshake process */
        tls13_startServerHandshakeThread(ctx);
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
        pthread_cancel(__client_handshake_thread);
        pthread_join(__client_handshake_thread, NULL);
        close(ctx->client_fd);
    }
    else if (ctx->role == TLS13_SERVER)
    {
        pthread_cancel(__server_handshake_thread);
        pthread_join(__server_handshake_thread, NULL);
        close(ctx->server_fd);
        close(ctx->client_fd);
    }
    else
    {
        assert(0);
    }
    pthread_cancel(__tls_transmit_thread);
    pthread_join(__tls_transmit_thread, NULL);
    // close(ctx->client_fd);

    tls13_deInit_ctx(ctx);
    tls13_ctx_queue(ctx, TLS13_CTX_DEQUEUE);
    if(!ctxHead || !ctxHead->next)
        tls13_ctx_queueDestroy();
}

void tls13_stateManager(tls13_context_t *ctx)
{
}

static tls13_cipherSuite_e tls13_selectCipherSuite(tls13_cipherSuite_e *cs, uint16_t csLen)
{
    uint8_t idx1;
    uint8_t idx2;;

    uint16_t *ptr2 = (uint16_t *)cs;

    for(idx1 = 0; idx1 < 4; idx1++){
        for(idx2 = 0; idx2 < (csLen/2); idx2++){
            printf("serverSupportedSuites[%d] --> %d compares with clientList[%d] --> %d\n",idx1, serverSupportedSuites[idx1], idx2, ptr2[idx2]);
            if(serverSupportedSuites[idx1] == ptr2[idx2])
            {
                printf("The opt choice for cipher suite is %d\n", serverSupportedSuites[idx1]);
                return serverSupportedSuites[idx1];
            }
        }
    }
    return TLS13_EMPTY_RENEGOTIATION_INFO_SCSV;
}

static tls13_signAlgos_e tls13_selectSignatureAlgo(tls13_signAlgos_e *sAlg, uint16_t sAlgLen)
{
    uint8_t idx1;
    uint8_t idx2;
    uint8_t len = sizeof(serverSupportedSignAlgms)/2;
    for(idx1 = 0; idx1 < len; idx1++){
        for(idx2 = 0; idx2 < sAlgLen; idx2++){
            if(serverSupportedSignAlgms[idx1] == sAlg[idx2])
            {
                return serverSupportedSignAlgms[idx1];
            }
        }
    }
    return TLS13_EMPTY_RENEGOTIATION_INFO_SCSV;
}

static tls13_cipherSuite_e tls13_getCipherSuite(const tls13_context_t *ctx)
{
    return ctx->serverCipherSuiteSupported;
}

static tls13_signAlgos_e tls13_getSignatureType(const tls13_context_t *ctx)
{
    //return TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256;
    return ctx->signatureAlgoSupported;
}

void print_context(tls13_context_t *ctx){

    int idx;
    printf("Role      : %d\n", ctx->role);
    printf("Client fd : %d\n", ctx->client_fd);
    printf("server fd : %d\n", ctx->server_fd);
    printf("Client ip : %d\n", ctx->client_ip);
    printf("Client port : %d\n", ctx->client_port);
    printf("Server ip: %d\n", ctx->server_ip);
    printf("Server port : %d\n", ctx->server_port);
    printf("Instance id : %d\n", ctx->instanceId);

    if(ctx->client_random != NULL){
        printf("Client Random: ");
        for(idx = 0; idx < TLS13_RANDOM_LEN; idx++){
            printf("%d", ctx->client_random[idx]);
        }
        printf("\n");
    }
    if(ctx->server_random != NULL){
        printf("Server Random: ");
        for(idx = 0; idx < TLS13_RANDOM_LEN; idx++){
            printf("%d", ctx->server_random[idx]);
        }
        printf("\n");
    }
    if(ctx->client_sessionId != NULL){
        printf("Client Session Id: ");
        for(idx = 0; idx < TLS13_SESSION_ID_LEN; idx++){
            printf("%d", ctx->client_sessionId[idx]);
        }
        printf("\n");
    }
    if(ctx->server_sessionId != NULL){
        printf("Server Session Id: ");
        for(idx = 0; idx < TLS13_SESSION_ID_LEN; idx++){
            printf("%d", ctx->server_sessionId[idx]);
        }
        printf("\n");
    }
    if(ctx->client_sessionId != NULL){
        printf("Client Session Id: ");
        for(idx = 0; idx < TLS13_SESSION_ID_LEN; idx++){
            printf("%d", ctx->client_sessionId[idx]);
        }
        printf("\n");
    }
    if(ctx->server_hostname_len > 0){
        printf("Server Hostname: %s\n", ctx->server_hostname);
    }

    printf("Key Type   : %d\n", ctx->keyType);
    printf("Key Length : %d\n", ctx->keyLen);
    if(ctx->client_publicKey != NULL){
        printf("Client Public Key: ");
        for(idx = 0; idx < ctx->keyLen; idx++){
            printf("%d", ctx->client_publicKey[idx]);
        }
        printf("\n");
    }
    if(ctx->server_publicKey != NULL){
        printf("Server Public Key: ");
        for(idx = 0; idx < ctx->keyLen; idx++){
            printf("%d", ctx->server_publicKey[idx]);
        }
        printf("\n");
    }

    print_capability(ctx->clientCapability, ctx->clientCapabilityLen);
    print_server_extensions(ctx->serverExtension, ctx->serverExtensionLen);
    //print_client_extensions(ctx->clientExtension, ctx->clientExtensionLen);

    printf("Supported Cipher Suite chosen: %d\n", ctx->serverCipherSuiteSupported);

    if(ctx->clientCert!= NULL){
        printf("Client Certificate: \n");
        for(idx = 0; idx < ctx->clientCertLen; idx++){
            printf("%d", ctx->clientCert[idx]);
        }
        printf("\n");
    }
    if(ctx->clientCertVerify != NULL){
        printf("Client Certificate Signature: \n");
        for(idx = 0; idx < ctx->clientCertVerifyLen; idx++){
            printf("%d", ctx->clientCertVerify[idx]);
        }
        printf("\n");
    }    
    if(ctx->serverCert!= NULL){
        printf("Server Certificate: \n");
        for(idx = 0; idx < ctx->serverCertLen; idx++){
            printf("%d", ctx->serverCert[idx]);
        }
        printf("\n");
    }
    if(ctx->serverCertVerify != NULL){
        printf("Server Certificate Signature: \n");
        for(idx = 0; idx < ctx->serverCertVerifyLen; idx++){
            printf("%d", ctx->serverCertVerify[idx]);
        }
        printf("\n");
    } 
    if(ctx->clientHandshakeSignature != NULL){
        printf("Client Handshake Signature: \n");
        for(idx = 0; idx < ctx->clientHandshakeSignLen; idx++){
            printf("%d", ctx->clientHandshakeSignature[idx]);
        }
        printf("\n");
    }
    if(ctx->serverHandshakeSignature != NULL){
        printf("Server Handshake Signature: \n");
        for(idx = 0; idx < ctx->serverHandshakeSignLen; idx++){
            printf("%d", ctx->serverHandshakeSignature[idx]);
        }
        printf("\n");
    } 

    printf("Handshake status: %d\n", ctx->handshakeCompleted);
    printf("Handshake Expiry status: %d\n", ctx->handshakeExpired);

    /* Calculated */
    if(ctx->serverHandshakeKey != NULL){
        printf("Server Handshake Key (Generated): ");
        for(idx = 0; idx < ctx->serverHandshakeKeyLen; idx++){
            printf("%d", ctx->serverHandshakeKey[idx]);
        }
        printf("\n");
    }
    if(ctx->serverHandshakeIV != NULL){
        printf("Server Handshake IV: ");
        for(idx = 0; idx < ctx->serverHandshakeIVLen; idx++){
            printf("%d", ctx->serverHandshakeIV[idx]);
        }
        printf("\n");
    }
 
    if(ctx->clientHandshakeKey != NULL){
        printf("Client Handshake Key (Generated): ");
        for(idx = 0; idx < ctx->clientHandshakeKeyLen; idx++){
            printf("%d", ctx->clientHandshakeKey[idx]);
        }
        printf("\n");
    }
    if(ctx->clientHandshakeIV != NULL){
        printf("Client Handshake IV: ");
        for(idx = 0; idx < ctx->clientHandshakeIVLen; idx++){
            printf("%d", ctx->clientHandshakeIV[idx]);
        }
        printf("\n");
    }
}

void fix_capability_endianess(tls13_capability_t *capability, uint16_t capabilityLen)
{
    uint8_t idx;
    if (capability == NULL)
        return;
    assert(capabilityLen > 0);

    //printf("Client Capability:\n");
    {
        tls13_cipherSuiteData_t *csd = capability->cipherSuiteList;
        //printf("Supported Cipher Suites: Size(%d)\n", capability->cipherSuiteLen);
        for(idx = 0; idx < (capability->cipherSuiteLen/2); idx++){
            csd[idx] = tls13_ntohs(csd[idx]);
        }
    }  
    {
        //printf("Supported Groups:\n");
        for(idx = 0; idx < (capability->supportedGrpLen/2); idx++){
            capability->supportedGrp[idx] = tls13_ntohs(capability->supportedGrp[idx]);
        }        
    }   
    {
        //printf("Signature Algorithms:\n");
        for(idx = 0; idx < (capability->signAlgoLen/2); idx++){
            capability->signAlgos[idx] = tls13_ntohs(capability->signAlgos[idx]);
        }        
    } 
    {
        //printf("Supported Versions:\n");
        for(idx = 0; idx < (capability->supportedVersionLen/2); idx++){
            capability->supportedVersions[idx] = tls13_ntohs(capability->supportedVersions[idx]);
        }        
    }
}

void print_capability(tls13_capability_t *capability, uint16_t capabilityLen)
{
    uint8_t idx;
    if (capability == NULL)
        return;
    assert(capabilityLen > 0);

    printf("Client Capability:\n");
    {
        tls13_cipherSuiteData_t *csd = capability->cipherSuiteList;
        printf("Supported Cipher Suites: Size(%d)\n", capability->cipherSuiteLen);
        for(idx = 0; idx < (capability->cipherSuiteLen/2); idx++){
            printf("[%d] %x\n", idx, csd[idx]);
        }
    }
    {
        tls13_compressionMethods_t *cml = capability->compressionMethodList;
        printf("Supported Compression Methods:\n");
        for(idx = 0; idx < (capability->compressionMethodLen); idx++){
            printf("[%d] %x\n", idx, cml[idx]);
        }        
    }
    {
        printf("Server Hostname Requested: size(%d)\n", capability->hostnameLen);
        for(idx = 0; idx < (capability->hostnameLen); idx++){
            printf("%c", capability->hostname[idx]);
        }
        printf("\n");     
    }
    {
        printf("Supported EC Points:\n");
        for(idx = 0; idx < (capability->ecFormatsLen); idx++){
            printf("[%d] %x\n", idx, capability->ecPoints[idx]);
        }        
    }    
    {
        printf("Supported Groups:\n");
        for(idx = 0; idx < (capability->supportedGrpLen/2); idx++){
            printf("[%d] %x\n", idx, capability->supportedGrp[idx]);
        }        
    }   
    {
        printf("Session Ticket:\n");
        for(idx = 0; idx < (capability->sessTktLen); idx++){
            printf("%x", capability->sessTkt[idx]);
        }
        printf("\n");      
    } 
    {
        printf("encrypt-then-MAC:\n");
        for(idx = 0; idx < (capability->eTMLen); idx++){
            printf("%x", capability->eTM[idx]);
        }
        printf("\n");      
    } 
    {
        printf("Extended Master Secret:\n");
        for(idx = 0; idx < (capability->extMasterSecretLen); idx++){
            printf("%x", capability->extMasterSecret[idx]);
        }
        printf("\n");      
    }
    {
        printf("Signature Algorithms:\n");
        for(idx = 0; idx < (capability->signAlgoLen/2); idx++){
            printf("[%d] %x\n", idx, capability->signAlgos[idx]);
        }        
    } 
    {
        printf("Supported Versions:\n");
        for(idx = 0; idx < (capability->supportedVersionLen/2); idx++){
            printf("[%d] %x\n", idx, capability->supportedVersions[idx]);
        }        
    } 
    {
        printf("PSK Key Exchange Modes:\n");
        for(idx = 0; idx < (capability->keyXchangeModesLen); idx++){
            printf("[%d] %x\n", idx, capability->keyXchangeModes[idx]);
        }        
    }
}

void print_server_extensions(tls13_serverExtensions_t *extensions, uint16_t extlen)
{

}

void print_client_extensions(tls13_clientExtensions_t *extensions, uint16_t extLen)
{

}