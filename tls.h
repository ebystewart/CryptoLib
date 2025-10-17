#ifndef _TLS_H_
#define _TLS_H_

#include <stdint.h>
#include <stdbool.h>

/* Ref: https://cabulous.medium.com/tls-1-2-andtls-1-3-handshake-walkthrough-4cfd0a798164
   Ref: https://www.ibm.com/docs/en/sdk-java-technology/8?topic=handshake-tls-12-protocol
   Sample Data: https://tls12.xargs.org/#open-all
*/

#define N_CIPHER_SUITE_SUPPORTED 10
#define N_COMPRESSION_METHOD_SUPPORTED 0
#define N_EXTENSION_SUPPORTED 3

typedef struct{
   uint8_t  recordType; /* 0x16 -> handshake record */ 
   uint16_t tlsVersion; /* 0x03 0x01 for TLS v1.3 */
   uint16_t recordLen;  /* Handshake message length in Bytes */
}tls12_recordHdr_t;

typedef struct{
   /* 0x01 for client hello; 
      0x02 for server hello; 
      0x0B for certificate; 
      0x0C for Server Key Exchange 
      0x0E for Server Hello Done 
      0x10 for Client Key Exchange
   */
   uint8_t  handshakeType;         
   uint32_t handshakeMsgLen : 24;  /* 3 Bytes length */
}tls12_handshakeHdr_t;

typedef struct{
   uint16_t cipherSuiteCode;
}tls12_cipherSuiteData_t;

typedef struct{
   uint8_t compRessionMethodCode;
}tls12_compressionMethods_t;

/* Extension Type
   0x00 0x00 - Server Name
   0x00 0x05 - Status Request
   0x00 0x0A - Supported groups
   0x00 0x0B - EC Points format
   0x00 0x0D - Signature Algorithms
   0xff 0x01 - Renegotiation info
   0x00 0x12 - Signed Certificate Timestamp
*/

/* Supported Groups
   00 1d - assigned value for the curve "x25519"
   00 17 - assigned value for the curve "secp256r1"
   00 18 - assigned value for the curve "secp384r1"
   00 19 - assigned value for the curve "secp521r1"
*/
typedef struct{
   uint16_t extType;
   uint16_t extDataLen;
   uint16_t subListSize;
   uint8_t *list;
}tsl12_extension_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint16_t version;   /* Client version - is usually the protocol version */
   uint8_t  clientRandom[32]; /* client random - 32Bytes */
   uint8_t  sessionId; /* Optional */
   uint16_t  cipherSuiteLen;
   tls12_cipherSuiteData_t cipherSuiteList[N_CIPHER_SUITE_SUPPORTED];
   uint8_t compressionMethodLength;
   tls12_compressionMethods_t compressionMethodList[N_COMPRESSION_METHOD_SUPPORTED];
   uint16_t extensionLen;
   tsl12_extension_t extensions[N_EXTENSION_SUPPORTED];
} tls12_clientHello_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint16_t version;   /* Server version - is usually the protocol version */
   uint8_t  serverRandom[32]; /* server random - 32Bytes */
   uint8_t  sessionId; /* Optional */
   uint16_t  cipherSuiteSelect;
   uint8_t compressionMethodSelect;
   uint16_t extensionLen;
   tsl12_extension_t renegotiationInfo;
} tls12_serverHello_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
} tls12_serverHelloDone_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint32_t totalCertificatesLen : 24;
   uint32_t certificateLen : 24;
   uint8_t *certificate;  /* Certificate in ASN.1 DER encoding */
}tls12_serverCertificate_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint8_t curveType;
   uint16_t curveId;
   uint8_t pubKeyLen;
   uint8_t *pubKey;  // should allocate some size 
   uint16_t signatureType;
   uint16_t signatureLen;
   uint8_t *signature;
}tls12_serverKeyXchange_t;

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