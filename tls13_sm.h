#ifndef _TLS13_SM_H_
#define _TLS13_SM_H_

#include <stdint.h>

#define TLS13_CLIENT_HELLO_LEN 254U 
#define TLS13_SERVER_HELLO_LEN 128U
#define TLS13_SERVER_WRAPPEDREC_LEN (6U + 28U + 840U + 286U + 74U) // 1234U
#define TLS13_CLIENT_FINISHED_LEN (6U + 74U) // 80U + data Length

#define TLS13_CLIENT_HELLO_MAX_LEN  1460
#define TLS13_SERVER_HELLO_MAX_LEN  1460
#define TLS13_CLIENT_FINISHED_MAX_LEN 1460

#define TLS13_SERVER_WRAPPEDREC_MAX_LEN 2400
#define TLS13_ALERT_LEN \
                (TLS13_RECORD_HEADER_SIZE + TLS13_HANDSHAKE_HEADER_SIZE + sizeof(tls13_alert_t))

#define TLS13_RECORD_HEADER_OFFSET 0U
#define TLS13_RECORD_HEADER_LENGTH_OFFSET 3U
#define TLS13_HANDSHAKE_HEADER_OFFSET 6U

#define TLS13_KEY_SIZE 32U

typedef enum {
    TLS13_CTX_ENQUEUE,
    TLS13_CTX_DEQUEUE
}tls13_ctxOperation_e;

typedef enum {
    TLS13_CLIENT,
    TLS13_SERVER
}tls13_ctxType_e;

typedef struct{
    /* sent or received */
    tls13_ctxType_e  role;
    int              client_fd;
    int              server_fd;
    uint32_t         client_ip;
    uint16_t         client_port;
    uint32_t         server_ip;
    uint16_t         server_port;
    uint8_t          instanceId;
    uint8_t          *client_random;
    uint8_t          *server_random;
    uint8_t          *client_sessionId;
    uint8_t          *server_sessionId;
    char             server_hostname[32];
    uint16_t         server_hostname_len; 
    uint16_t         keyType;
    uint16_t         keyLen;
    uint8_t          *client_publicKey;
    uint8_t          *server_publicKey;
    tls13_capability_t *clientCapability;
    uint16_t           clientCapabilityLen;
    tls13_serverExtensions_t *serverExtension;
    uint16_t                 serverExtensionLen;
    tls13_clientExtensions_t *clientExtension;
    uint16_t                 clientExtensionLen;
    tls13_cipherSuite_e serverCipherSuiteSupported;
    uint8_t           *clientCert;
    uint16_t          clientCertLen;
    uint8_t           *clientCertVerify;
    uint16_t          clientCertVerifyLen;
    uint8_t           *serverCert;
    uint16_t          serverCertLen;
    uint8_t           *serverCertVerify;
    uint16_t          serverCertVerifyLen;
    uint8_t           *clientHandshakeSignature;
    uint16_t          clientHandshakeSignLen;
    uint8_t           *serverHandshakeSignature;
    uint16_t          serverHandshakeSignLen;
    bool              handshakeCompleted;
    bool              handshakeExpired;
    /* Calculated */
    uint8_t           *serverHandshakeKey;
    uint16_t          serverHandshakeKeyLen;
    uint8_t           *serverHandshakeIV;
    uint16_t          serverHandshakeIVLen;
    uint8_t           *clientHandshakeKey;
    uint16_t          clientHandshakeKeyLen;
    uint8_t           *clientHandshakeIV;
    uint16_t          clientHandshakeIVLen;
}tls13_context_t;



void tls13_init(tls13_context_t *ctx);

void print_context(tls13_context_t *ctx);

void print_capability(tls13_capability_t *capability, uint16_t capabilityLen);

void print_server_extensions(tls13_serverExtensions_t *extensions, uint16_t extlen);

void print_client_extensions(tls13_clientExtensions_t *extensions, uint16_t extLen);

#endif