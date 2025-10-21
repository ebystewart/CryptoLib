#ifndef _TLS12_H_
#define _TLS12_H_

#include <stdint.h>
#include <stdbool.h>

/* Ref: https://cabulous.medium.com/tls-1-2-andtls-1-3-handshake-walkthrough-4cfd0a798164
   Ref: https://www.ibm.com/docs/en/sdk-java-technology/8?topic=handshake-tls-12-protocol
   Sample Data: https://tls12.xargs.org/#open-all

   ________                                                      __________
   |Client|                                                      | Server |
   --------                                                      ----------
      |                                                               |-------------------------------------------------
      |-----Client Hello ------------------------------------------->>|                                            |
      |                                                               |                                            |
      |<<------------------------------------------Server Hello-------|                                            |
      |                                                               |                                            |
      |<<----------------------------------------- Certificate--------|                                            |
      |                                                               |                                            |
      |<<----------------------------------------- Server Hello Done--| First Round trip of handshake ends         |
      |                                                               |                                            |
      |--- Client Key Exchange (pre-Master Secret)------------------>>|                                            |
      |                                                               |                                 TLS 1.2 Handshake 
      |--- Change Cipher Spec -------------------------------------->>|                                            |
      |                                                               |                                            |
      |--- Finished (Encrypted verification)------------------------>>|                                            |
      |                                                               |                                            |
      |<<----------------------- Change Cipher Spec ------------------|                                            |
      |                                                               |                                            |
      |<<----------------------- Finished (Encrypted verification)----| Second round trip handshake ends           |
      |                                                               |--------------------------------------------------
      |                                                               |
      |<<<<------------------ Encrypted Data ---------------------->>>|
      |                                                               |
*/

#define N_CIPHER_SUITE_SUPPORTED
#define N_COMPRESSION_METHOD_SUPPORTED 0
#define N_EXTENSION_SUPPORTED 

typedef struct{
   /* 0x16 -> handshake record; 
      0x17 -> application data; 
      0x15 -> alert record 
   */ 
   uint8_t  recordType;
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
      0x14 for finished
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
   uint8_t list[0];
}tsl12_extension_t;

typedef struct{
   tls12_recordHdr_t          recordHeader;
   tls12_handshakeHdr_t       handshakeHeader;
   uint16_t                   version;                  /* Client version - is usually the protocol version */
   uint8_t                    clientRandom[32];         /* client random - 32Bytes */
   uint8_t                    sessionId;                /* Optional */
   uint16_t                   cipherSuiteLen;
   tls12_cipherSuiteData_t    cipherSuiteList[0];       /* N_CIPHER_SUITE_SUPPORTED */
   uint8_t                    compressionMethodLength;
   tls12_compressionMethods_t compressionMethodList[0]; /* N_COMPRESSION_METHOD_SUPPORTED */
   uint16_t                   extensionLen;
   tsl12_extension_t          extensions[0];            /* N_EXTENSION_SUPPORTED */
} tls12_clientHello_t;

typedef struct{
   tls12_recordHdr_t    recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint16_t             version;                  /* Server version - is usually the protocol version */
   uint8_t              serverRandom[32];         /* server random - 32Bytes */
   uint8_t              sessionId;                /* Optional */
   uint16_t             cipherSuiteSelect;
   uint8_t              compressionMethodSelect;
   uint16_t             extensionLen;
   tsl12_extension_t    renegotiationInfo;
} tls12_serverHello_t;

typedef struct{
   tls12_recordHdr_t    recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
} tls12_serverHelloDone_t;

typedef struct{
   tls12_recordHdr_t    recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint32_t             totalCertificatesLen : 24;
   uint32_t             certificateLen : 24;
   uint8_t              certificate[0];            /* Certificate in ASN.1 DER encoding */
}tls12_serverCertificate_t;

typedef struct{
   tls12_recordHdr_t    recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint8_t              curveType;
   uint16_t             curveId;
   uint8_t              pubKeyLen;
   uint8_t              pubKey[0];          // should allocate some size 
   uint16_t             signatureType;
   uint16_t             signatureLen;
   uint8_t              signature[0];
}tls12_serverKeyXchange_t;

typedef struct{
   tls12_recordHdr_t    recordHeader;
   tls12_handshakeHdr_t handshakeHeader;
   uint8_t              pubKeyLen;
   uint8_t              pubKey[0];  // should allocate some size 
}tls12_clientKeyXchange_t;

/* This is a common structure for both client and server change cipher spec messages */
typedef struct{
   tls12_recordHdr_t recordHeader;
   uint8_t           payload;       /* 1 Byte payload usually 0x01 */
}tls12_changeCipherSpec_t;

/* This is a common structure for both client and server handshake finished messages */
typedef struct{
   tls12_recordHdr_t    recordHeader;
   uint8_t              encryptIv[0];   // size to be studied
   uint8_t              encryptData[0]; // size to be studied
   tls12_handshakeHdr_t handshakeHeader;
   /* hash of master secret and payload of all handshake records */
   uint8_t              verifyData[0];  // size to be studied
}tls12_handshakeFinished_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   uint8_t           encryptIv[0];   // size to be studied
   uint8_t           encryptData[0]; // size to be studied
   uint8_t           appData[0];     // size decided during run-time
}tls12_data_t;

typedef struct{
   tls12_recordHdr_t recordHeader;
   uint8_t           encryptIv[0];   // size to be studied
   uint8_t           encryptData[0]; // size to be studied
   uint8_t           alertLevel;     /* 0x01 -> warning */
   uint8_t           alertType;      /* 0x00 -> close notify */
}tls12_clientCloseNotify_t;

void tls12_prepareClientHello(tls12_clientHello_t *helloframe);

//void tls_receiveClientHello(void);

void tls12_prepareServerHello(tls12_serverHello_t *helloFrame);

void tls12_prepareServerHelloDone(tls12_serverHelloDone_t *helloDoneFrame);

//void tls_receiveServerHello(void);

//void tls_receiveServerHelloDone(void);

void tls12_prepareServerCertificate(tls12_serverCertificate_t *serverCertificateFrame);

//void tls_receiveServerCertificate(void);

void tls12_requestCertificate(void);

void tls12_verifyCertificate(void);

void tls12_clientKeyExchange(tls12_clientKeyXchange_t *xchange);

void tls12_serverKeyExchange(tls12_serverKeyXchange_t *xchange);

void tls12_prepareClientCloseNotify(tls12_clientCloseNotify_t *closeNotifyFrame);

/* common client & server APIs */
void tls12_prapareChangeCipherSpec(tls12_changeCipherSpec_t *cipherSpecFrame);

void tls12_prepareHandshakeFinished(tls12_handshakeFinished_t *handshakeFinFrame);

void tls12_prepareData(uint8_t *data, uint16_t dataLen, tls12_data_t *tlsDataFrame);

#endif