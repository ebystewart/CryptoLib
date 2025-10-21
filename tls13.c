#include <stdlib.h>
#include "tls13.h"
#include "math.h"


void tls13_prepareClientHello(tls13_clientHello_t *clientHello)
{
    tls13_clientHello_t *clientHelloTmp = calloc(1, sizeof(tls13_clientHello_t) + 100);

    /* Record header update */
    clientHelloTmp->recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    clientHelloTmp->recordHeader.protoVersion = TLS13_PROTO_VERSION;

    /* handshake header update */
    clientHelloTmp->handshakeHeader.handshakeType = TLS13_HST_CLIENT_HELLO;

    clientHelloTmp->clientVersion = TLS13_PROTO_VERSION;
    /* get a 32 Byte random value */
    //clientHelloTmp->clientRandom =
    clientHelloTmp->sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Get a 16 Byte Session Id */
    //clientHelloTmp->sessionId =

    /* copy the Ciphersuite data */
    clientHelloTmp->cipherSuiteLen = TLS13_CIPHERSUITE_LEN; // this also need a macro to augment dynamic offset
    tls13_cipherSuiteData_t *csd = GET_CLIENTHELLO_CIPHERSUITELIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN);
    csd[0] = TLS13_AES_128_GCM_SHA256;
    csd[1] = TLS13_AES_256_GCM_SHA384;
    csd[2] = TLS13_CHACHA20_POLY1305_SHA256;

    /* copy the compression methods */
    tls13_compressionMethods_t *cmpMthd = GET_CLIENTHELLO_CMPMTHDLIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN);

    clientHelloTmp->handshakeHeader.handshakeMsgLen = 0; // to be updated
    clientHelloTmp->recordHeader.recordLen = 0; // To be updated at the end
}