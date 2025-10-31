#ifndef _TLS13_SM_H_
#define _TLS13_SM_H_

#include <stdint.h>

typedef enum {
    TLS13_CTX_ENQUEUE,
    TLS13_CTX_DEQUEUE
}tls13_ctxOperation_e;

typedef enum {
    TLS13_CLIENT,
    TLS13_SERVER
}tls13_ctxType_e;

typedef struct{
    int fd;
    int comm_fd;
    uint32_t ip;
    uint16_t port;
    uint8_t          instanceId;
    tls13_ctxType_e  role;
    uint8_t          *random;
    uint8_t          *sessionId;   
    uint16_t         keyType;
    uint16_t         keyLen;
    uint8_t          *publicKey;
}tls13_context_t;


#endif