#ifndef _TLS13_H_
#define _TLS13_H_

/*
   Ref: https://tls13.xargs.org/
   Ref: https://www.youtube.com/watch?v=JA0vaIb4158
   ________                                                      __________
   |Client|                                                      | Server |
   --------                                                      ----------
      |                                                               | ----------------------------------------------------------------------------------------
      |-----Client Hello ------------------------------------------->>|                                                                                       |
      |                                                               |                                                                                       |
      |<<------------------------------------------Server Hello-------| (ext, cert, cert verify, finished, certificate request (if mutual auth is required))  |
      |                                                               |                                                                                       |
      |<<----------------## Server can send encrypted data here ##----|                                                                                       |
      |                                                               | Only one round trip                                                        TLS 1.3 Handshake
      |--- Finished ----------------------------------------------->>>| cert, cert verify (if client cert is requested)                                       |
      |                                                               | ----------------------------------------------------------------------------------------
      |<<<<------------------ Encrypted Data ---------------------->>>|
      |                                                               |
*/

#include <stdint.h>
#include <stdbool.h>
#include "tls13_extensions.h"


#define TLS13_SESSION_ID_LEN 16
#define TLS13_CIPHERSUITE_LEN 3
#define TLS13_PROTO_VERSION 0x0301

typedef enum {
   TLS13_ALERT_RECORD     = 0x15,
   TLS13_HANDSHAKE_RECORD = 0x16,
   TLS13_APPDATA_RECORD   = 0x17
}tls13_recordType_e;

typedef enum {
   TLS13_HST_CLIENT_HELLO       = 0x01,
   TLS13_HST_SERVER_HELLO       = 0x02,
   TLS13_HST_CERTIFICATE        = 0x0B,
   TLS13_HST_SERVER_KEY_XCHNGE  = 0x0C,
   TLS13_HST_SERVER_HELLO_DONE  = 0x0E,
   TLS13_HST_CERTIFICATE_VERIFY = 0x0F,
   TLS13_HST_CLIENT_KEY_XCHNGE  = 0x10,
   TLS13_HST_FINISHED           = 0x14 
}tls13_handshakeType_e;

typedef enum {
   TLS13_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF,
   TLS13_AES_128_GCM_SHA256            = 0x1301,
   TLS13_AES_256_GCM_SHA384            = 0x1302,
   TLS13_CHACHA20_POLY1305_SHA256      = 0x1303
}tls13_cipherSuite_e;

#pragma pack(push, 1)

typedef struct{
   /* 0x16 -> handshake record; 
      0x17 -> application data; 
      0x15 -> alert record 
   */ 
   uint8_t  recordType;
   uint16_t protoVersion; /* 0x03 0x01 for TLS v1.3 */
   uint16_t recordLen;  /* Handshake message length in Bytes */
}tls13_recordHdr_t;

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
}tls13_handshakeHdr_t;

/* 
   13 02 - assigned value for TLS_AES_256_GCM_SHA384
   13 03 - assigned value for TLS_CHACHA20_POLY1305_SHA256
   13 01 - assigned value for TLS_AES_128_GCM_SHA256
   00 ff - assigned value for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
*/
typedef uint16_t tls13_cipherSuiteData_t;

/*
   00 - assigned value for "null" compression
*/
typedef uint8_t tls13_compressionMethods_t;

/* Client Hello Extensions */
typedef struct{
   tls13_extensionSNI_t       extSNI;                   /* Server Name Indication (SNI) Extension */
   tls13_extension2211_t      extECP;                   /* EC Point Formats extension */
   tls13_extension2222_t      extSupprotedGrp;          /* Supported Groups Extension */
   tls13_extensionNULL_t      extSessionTicket;         /* extension data length is 0 */
   tls13_extensionNULL_t      extEncryptThenMAC;        /* extension data length is 0 */
   tls13_extensionNULL_t      extExtendedMasterSecret;  /* extension data length is 0 */
   tls13_extension2222_t      extSignatureAlgos;        /* Signature Algorithms Extension */
   tls13_extension2212_t      extSupportedVers;
   tls13_extension2211_t      extPSKExchangeModes;
   tls13_extensionKeyShare_t  extkeyShare;
}tls13_clientExtensions_t;

/* Client Hello structure */
typedef struct{
   tls13_recordHdr_t          recordHeader;
   tls13_handshakeHdr_t       handshakeHeader;
   uint16_t                   clientVersion;            /* Client version - is usually the protocol version */
   uint8_t                    clientRandom[32];         /* client random - 32Bytes   */
   uint8_t                    sessionIdLen;             /* Session Id length         */
   uint8_t                    sessionId[0];             /* Session Id - usually fake */
   uint16_t                   cipherSuiteLen;
   tls13_cipherSuiteData_t    cipherSuiteList[0];       /* N_CIPHER_SUITE_SUPPORTED  */
   uint8_t                    compressionMethodLength;
   tls13_compressionMethods_t compressionMethodList[0]; /* N_COMPRESSION_METHOD_SUPPORTED         */
   uint16_t                   extLen;
   tls13_clientExtensions_t   clientExt;
} tls13_clientHello_t;

/* Server Hello Extensions */
typedef struct{
   tls13_extension222_t       extSupportedVers;
   tls13_extensionKeyShare_t  extkeyShare;
}tls13_serverExtensions_t;

typedef struct{
    tls13_recordHdr_t           recordHeader;
    tls13_handshakeHdr_t        handshakeHeader;
    uint16_t                    serverVersion;            /* Server version - is usually the protocol version */
    uint8_t                     serverRandom[32];         /* server random - 32Bytes */
    uint8_t                     sessionIdLen;             /* Optional */
    uint8_t                     sessionId[0];             /* usually fake */
    uint16_t                    cipherSuiteSelect;
    uint8_t                     compressionMethodSelect;
    uint16_t                    extensionLen;
    tls13_serverExtensions_t    serverExt;
} tls13_serverHello_t;

/* server change cipher spec - for compatability */
typedef struct{
   tls13_recordHdr_t recordHeader;
   uint8_t           payload;       /* 1 Byte payload usually 0x01 */
}tls12_serverChangeCipherSpec_t;

typedef struct {
   uint32_t     certLen : 24;
   uint8_t      cert[0];
   uint16_t     certExtension;
}tls13_cert_t;

typedef struct {
   tls13_handshakeHdr_t handshakeHdr;     /*  type 0x0B (certificate) */
   uint8_t              requestContext;
   uint32_t             payloadLen : 24;
   tls13_cert_t         cert[0];
}tls13_serverCert_t;

typedef struct {
   uint16_t    signType;
   uint16_t    signLen;
   uint8_t     sugn[0];
}tls13_signature_t;

typedef struct {
   tls13_handshakeHdr_t handshakeHdr;    /* 0x0f (certificate verify) */
   tls13_signature_t    sign;
}tls13_serverCertVerify_t;

typedef struct {
   tls13_handshakeHdr_t handshakeHdr; /*  0x04 (new session ticket */
   uint32_t             ticketLifetime;
   uint32_t             ticketAgeAdd;
   uint8_t              nounceLen;
   uint8_t              nounce[0];
   uint16_t             sessionTicketLen;
   uint8_t              sessionTicket[0];
   uint16_t             ticketExtensionLen;
}tls13_serverNewSessionTicket_t;

typedef struct {
   tls13_recordHdr_t recordHeader;     /* 0x17 (application data) */
   uint8_t           encryptedData[0]; /* Data encrypted with the server handshake key */
   uint8_t           authTag[16];      /* AEAD authentication tag */
   uint8_t           encryExt[0];      /* could be Server Certificate  (tls13_serverCert_t) [or] server cert verify [or]  server finished [or] client finished */
   uint8_t           recordType;       /* 0x16 (handshake record); 0x17 (application data)*/
}tls13_wrappedRecord_t;

#pragma pop

/* Macros for pointer access */
#define GET_CLIENTHELLO_CIPHERSUITELIST_PTR(clientHelloPtr, sessionIdLen)         \
               ((tls13_cipherSuiteData_t *)((((tls13_clientHello_t *)0)->cipherSuiteLen) + sessionIdLen))

#define GET_CLIENTHELLO_CMPMTHDLIST_PTR(clientHelloPtr, sessionIdLen, cipherSuiteLen)      \
               ((tls13_compressionMethods_t *)((((tls13_clientHello_t *)0)->compressionMethodList) + sessionIdLen + cipherSuiteLen))

#define GET_CLIENTHELLO_CLIENTEXT_PTR(clientHelloPtr, sessionIdLen, cipherSuiteLen, cmpMthdLen)      \
               ((tls13_clientExtensions_t *)((((tls13_clientHello_t *)0)->clientExt) + sessionIdLen + cipherSuiteLen + cmpMthdLen))

void tls13_prepareClientHello(tls13_clientHello_t *clientHello);

#endif