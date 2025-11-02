#ifndef _TLS13_SM_H_
#define _TLS13_SM_H_

#include <stdint.h>

#define TLS13_CLIENT_HELLO_LEN 2400 // approximate value; need to revisit

typedef enum {
    TLS13_CTX_ENQUEUE,
    TLS13_CTX_DEQUEUE
}tls13_ctxOperation_e;

typedef enum {
    TLS13_CLIENT,
    TLS13_SERVER
}tls13_ctxType_e;

typedef struct{
    tls13_ctxType_e  role;
    int              client_fd;
    int              server_fd;
    int              client_max_fd;
    int              server_max_fd;
    uint32_t         client_ip;
    uint16_t         client_port;
    uint32_t         server_ip;
    uint16_t         server_port;
    uint8_t          instanceId;
    uint8_t          *client_random;
    uint8_t          *server_random;
    uint8_t          *client_sessionId;
    uint8_t          *server_sessionId;  
    uint16_t         keyType;
    uint16_t         keyLen;
    uint8_t          *client_publicKey;
    uint8_t          *server_publicKey;
}tls13_context_t;


#endif