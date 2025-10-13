#ifndef _TLS_H_
#define _TLS_H_

/* Ref: https://cabulous.medium.com/tls-1-2-andtls-1-3-handshake-walkthrough-4cfd0a798164
   Ref: https://www.ibm.com/docs/en/sdk-java-technology/8?topic=handshake-tls-12-protocol
   Sample Data: https://tls12.xargs.org/#open-all
*/

void tls_sendClientHello(void);

//void tls_receiveClientHello(void);

void tls_sendServerHello(void);

void tls_sendServerHelloDone(void);

//void tls_receiveServerHello(void);

//void tls_receiveServerHelloDone(void);

void tls_sendCertificate(void);

//void tls_receiveCertificate(void);

void tls_requestCertificate(void);

void tls_verifyCertificate(void);


void tls_clientKeyExchange(void);

void tls_serverKeyExchange(void);

void 

#endif