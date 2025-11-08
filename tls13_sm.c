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
#include <unistd.h>
#include "tls13.h"
#include "tls13_sm.h"
#include "math.h"
#include "rand.h"
#include "ecc.h"

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

static void tls13_cxt_queueInit(void);

static tls13_ctxDatabase_t *tls13_cxt_queueFind(tls13_context_t *ctx);

static void tls13_cxt_queueInsert(tls13_context_t *ctx);

static void tls13_cxt_queueDelete(tls13_context_t *ctx);

static void tls13_ctx_queue(tls13_context_t *ctx, tls13_ctxOperation_e op);

static void tls13_hash_and_sign(uint8_t *clientHelloRec, uint16_t clientHelloRecLen, 
                        uint8_t *serverHelloRec, uint16_t serverHelloRecLen,
                        uint8_t *clientRecExclFin, uint16_t clientRecExclFinLen,
                        tls13_cipherSuite_e cipherSuite, uint8_t *handshakeSign);

static void tls13_cxt_queueInit(void)
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
    ctxTmp = ctxTmp->next;
    while (ctxTmp->next != NULL)
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
static uint16_t portNum = 27000;
static uint16_t tls13_getNextPortNumber(void)
{
    return (portNum + 4);
}

static uint32_t tls13_getIPAddress(void)
{
    return 0;
}

static void tls13_hash_and_sign(uint8_t *clientHelloRec, uint16_t clientHelloRecLen, 
                        uint8_t *serverHelloRec, uint16_t serverHelloRecLen,
                        uint8_t *clientRecExclFin, uint16_t clientRecExclFinLen,
                        tls13_cipherSuite_e cipherSuite, uint8_t *handshakeSign)
{

}

static void *__client_handshake_thread(void *arg)
{
    int opt = 1;
    bool serverHelloReceived = false;
    bool serverWrappedRecReceived = false;
    tls13_cipherSuite_e serverCipherSuiteSupported;
    uint16_t handshakeSignLen;
    tls13_recordType_e first_record;
    tls13_context_t *ctx = (tls13_context_t *)arg;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    /* We need to keep the backup of all the messages for signature calculation for finished record */
    /* assuming the following messages:
     *  1. Client hello (sent)
     *  2. Server hello (received)
     *  3. Client Finished (this has the signature)
    */
    uint8_t *clientHello_pkt      = calloc(1, TLS13_CLIENT_HELLO_LEN); // client hello may not fit in one frame
    uint8_t *temp                 = calloc(1, TLS13_SERVER_HELLO_MAX_LEN);
    uint8_t *serverHello_pkt      = calloc(1, TLS13_SERVER_HELLO_MAX_LEN); // If pkt is more than max size, we may receive as 2 pkts; need to handle this
    uint8_t *serverWrappedRec_pkt = calloc(1, TLS13_SERVER_WRAPPEDREC_MAX_LEN);
    uint8_t *clientFinish_pkt     = calloc(1, TLS13_CLIENT_FINISHED_LEN);

    /* Prepare the cleint hello pkt */
    tls13_prepareClientHello(ctx->client_random, ctx->client_sessionId, ctx->server_hostname, ctx->client_publicKey, ctx->client_publicKey, clientHello_pkt);

    /* Send the client hello pkt over TCP to the destined socket */
    int rc = send(ctx->client_fd, clientHello_pkt, TLS13_CLIENT_HELLO_LEN, 0);

    /* Wait for the server hello response to be received */
    while (serverHelloReceived == false || serverWrappedRecReceived == false)
    {

        pthread_testcancel();
        {
            rc = recv(ctx->client_fd, temp, sizeof(temp), 0);// NULL, 0);
            first_record = temp[TLS13_RECORD_HEADER_OFFSET];
            if (temp[TLS13_HANDSHAKE_HEADER_OFFSET] == TLS13_HST_SERVER_HELLO && first_record == TLS13_HANDSHAKE_RECORD)
            {
                serverHelloReceived == true;
                memcpy(serverHello_pkt, temp, sizeof(serverHello_pkt));
                tls13_extractServerHello(ctx->server_random, ctx->client_sessionId, &serverCipherSuiteSupported, ctx->client_publicKey, \
                    &ctx->keyLen, &ctx->keyType, (tls13_serverExtensions_t *)ctx->serverExtension, &ctx->serverExtensionLen, serverHello_pkt); // need to update args
            }
            if((temp[TLS13_HANDSHAKE_HEADER_OFFSET] == TLS13_HST_CERTIFICATE || \
                temp[TLS13_HANDSHAKE_HEADER_OFFSET] == TLS13_HST_CERTIFICATE_VERIFY || \
                temp[TLS13_HANDSHAKE_HEADER_OFFSET] == TLS13_HST_CERTIFICATE_REQUEST || \
                temp[TLS13_HANDSHAKE_HEADER_OFFSET] == TLS13_HST_CERTIFICATE_REQUEST) \
                && first_record == TLS13_APPDATA_RECORD)
            {

                memcpy(serverWrappedRec_pkt, temp, sizeof(serverWrappedRec_pkt));
                tls13_extractServerWrappedRecord(serverWrappedRec_pkt, ctx->serverCert, ctx->serverHandshakeSignature, ctx->serverCertVerify, &ctx->serverCertVerifyLen);
                serverWrappedRecReceived = true;
            }
        }
    }
    /* Extract the hash lengh from the cipher suite supported 
       This will be helpful to compute the signature */
    if (serverCipherSuiteSupported == TLS13_AES_128_GCM_SHA256 || serverCipherSuiteSupported == TLS13_CHACHA20_POLY1305_SHA256){
        handshakeSignLen = 256U;
    }else if(serverCipherSuiteSupported == TLS13_AES_256_GCM_SHA384){
        handshakeSignLen = 384U;
    }
    else{
        /* assert error as unspoorted TLS 1.3 cupher suiite is used */
        assert(0);
    }

    uint8_t *handshakeSign = calloc(1, handshakeSignLen);

    /* At this point, we should be able to calculate the hash and sign it */
    tls13_hash_and_sign(clientHello_pkt, TLS13_CLIENT_HELLO_LEN, 
                        serverHello_pkt, TLS13_SERVER_HELLO_LEN,
                        clientFinish_pkt, TLS13_CLIENT_FINISHED_LEN - handshakeSignLen, //should use an offset to exclude the handshake record completely
                        serverCipherSuiteSupported, handshakeSign);

    /* Prepare the wrapped record (certificate, certificateVerify, finished)*/
    // need to handle if certificate and certverify also needs to be sent
    tls13_prepareClientWrappedRecord(handshakeSign, handshakeSignLen, "hello", strlen("hello"), clientFinish_pkt);

    /* check if the handshake is successful */
    // actually server handshake signature is calculated and compared with the received one
    if (0 != memcmp(ctx->clientHandshakeSignature, ctx->serverHandshakeSignature, ctx->clientHandshakeSignLen)){
        tls13_alert_t alert;
        uint8_t *alert_pkt = calloc(1, TLS13_ALERT_LEN);
        alert.level = TLS13_ALERT_FATAL;
        alert.description = TLS13_HANDSHAKE_FAILURE;
        tls13_prepareAlertRecord(&alert, alert_pkt);
        send(ctx->client_fd, alert_pkt, TLS13_ALERT_LEN, 0);
        ctx->handshakeExpired = false;
        
        /* handshake failed - terminate the thread */
        pthread_exit(0);
    }
    send(ctx->client_fd, clientFinish_pkt, TLS13_CLIENT_FINISHED_LEN, 0);
    ctx->handshakeCompleted = true;
    ctx->handshakeExpired = false;

    free(clientHello_pkt);
    free(temp);
    free(serverHello_pkt);
    free(serverWrappedRec_pkt);
    free(clientFinish_pkt);
    free(handshakeSign);

    /* This thread should terminate when the handshake is complete */
    pthread_exit(0);
}

static void *__server_handshake_thread(void *arg)
{
    int opt = 1;
    uint8_t addr_len;
    bool clientHelloReceived = false;
    tls13_context_t *ctx = (tls13_context_t *)arg;

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = ctx->client_port;
    client_addr.sin_addr.s_addr = ctx->client_ip;
    socklen_t addr_size = sizeof(client_addr);

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);  // joinable ??

    /* We need to keep the backup of all the messages for signature calculation for finished record */
    /* assuming the following messages:
     *  1. Client hello (received)
     *  2. Server hello (sent)
     *  3. Server Finished (this has the signature)
    */
    uint8_t *clientHello_pkt = calloc(1, TLS13_CLIENT_HELLO_MAX_LEN);
    uint8_t *serverHello_pkt = calloc(1, TLS13_SERVER_HELLO_MAX_LEN); // If pkt is more than max size, we may receive as 2 pkts; need to handle this
    uint8_t *clientFinish_pkt = calloc(1, TLS13_CLIENT_FINISHED_LEN);

    if (listen(ctx->client_fd, 20) < 0U)
    {
        printf("listen failed \n");
        exit(1);
    }
    while (clientHelloReceived == false)
    {
        pthread_testcancel();
        ctx->client_fd = accept(ctx->server_fd, (struct sockaddr *)&client_addr, &addr_size);

        /* recieve client hello first */
        {
            int rc = recv(ctx->client_fd, clientHello_pkt, TLS13_CLIENT_HELLO_MAX_LEN, 0);// (struct sockaddr *)&server_addr, &addr_len);

            tls13_extractClientHello(ctx->client_random, ctx->client_sessionId, NULL, ctx->clientCapability, ctx->client_publicKey, ctx->keyLen, clientHello_pkt);
            /* Receive the server hello and extract the data */
            clientHelloReceived = true;
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
    server_addr.sin_addr.s_addr = ctx->server_ip;//INADDR_ANY;//0x7F000001UL; //tls13_getIPAddress();
    server_addr.sin_port = ctx->server_port;

    /* IP also needs to be updated */

    ctx->client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // SOCK_DGRAM, IPPROTO_UDP);
    if(ctx->client_fd < 0){
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    if(connect(ctx->client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr) < 0))
    {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }
}

static void init_serverSocket(tls13_context_t *ctx)
{
    int opt = 1;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = ctx->server_ip;
    server_addr.sin_port = ctx->client_port;

    ctx->server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // SOCK_DGRAM, IPPROTO_UDP);

    if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0U)
    {
        printf("%s(): Setting of socket option to reuse address failed.\n", __FUNCTION__);
        exit(1);
    }
    if (setsockopt(ctx->server_fd, SOL_SOCKET, SO_REUSEPORT, (char *)&opt, sizeof(opt)) > 0U)
    {
        printf("%s(): Setting of sock option to reuse port address failed\n", __FUNCTION__);
        exit(1);
    }

    /* IP also needs to be updated */

    if (bind(ctx->server_fd, (const struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0)
    {
        printf("socket bind failed for instance %d\n", ctx->instanceId);
        exit(1);
    }
}

void tls13_init(tls13_context_t *ctx)
{
    assert(ctx->server_ip > 0);
    assert(ctx->server_port > 0);
    assert(ctx->client_ip > 0);
    assert(ctx->client_port > 0);

    /* create the context entry in database */
    tls13_ctx_queue(ctx, TLS13_CTX_ENQUEUE);

    if (ctx->role == TLS13_CLIENT)
    {
        /* Create and bind a socket */
        init_clientSocket(ctx);
        /* Start the client handshake process */
        tls13_startClientHandshakeThread(ctx);
    }
    else if (ctx->role == TLS13_SERVER)
    {
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
    }
    else
    {
        assert(0);
    }
    pthread_cancel(__tls_transmit_thread);
    pthread_join(__tls_transmit_thread, NULL);
    // close(ctx->client_fd);

    tls13_ctx_queue(ctx, TLS13_CTX_DEQUEUE);
}

void tls13_stateManager(tls13_context_t *ctx)
{
}