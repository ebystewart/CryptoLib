#ifndef _TLS13_H_
#define _TLS13_H_

#include <stdint.h>
#include <stdbool.h>
#include "tls13_extensions.h"

/*
   Ref: https://tls13.xargs.org/
   Ref: https://www.youtube.com/watch?v=JA0vaIb4158
   Ref: https://www.youtube.com/watch?v=Cq6yj9se9M4 -> TLS 1.3 visualization in wireshark
   ________                                                      __________
   |Client|                                                      | Server |
   --------                                                      ----------
      |                                                               | ----------------------------------------------------------------------------------------
      |-----Client Hello ------------------------------------------->>|                                                                                       |
      |                                                               |                                                                                       |
      |<<------------------------------------------Server Hello-------| (ext, cert, cert verify, finished, certificate request (if mutual auth is required))  |
      |                                                               |                                                                                       |
      |<<----------------## Server can send encrypted data here ##----| change cipher spec, app data                                                                                      |
      |                                                               | Only one round trip                                                        TLS 1.3 Handshake
      |--- Finished ----------------------------------------------->>>| cert, cert verify (if client cert is requested)                                       |
      |                                                               | ----------------------------------------------------------------------------------------
      |<<<<------------------ Encrypted Data ---------------------->>>|
      |                                                               |
*/

#define TLS13_SESSION_ID_LEN 32
#define TLS13_CIPHERSUITE_LEN 8
#define TLS13_COMPRESSIONMETHD_LEN 1U
#define TLS13_PROTO_VERSION 0x0301
#define TLS13_VERSION 0x0304
#define TLS12_PROTO_VERSION 0x0303
#define TLS13_RANDOM_LEN 32
#define TLS13_RECORD_AUTHTAG_LEN 16U
#define TLS13_RECORD_HEADER_SIZE 5
#define TLS13_HANDSHAKE_HEADER_SIZE 4
#define TLS13_HANDSHAKE_LENGTH_FIELD_SIZE 3
#define TLS13_HANDSHSKE_TYPE_OFFSET (TLS13_RECORD_HEADER_SIZE)
#define TLS13_CLIENT_EXT_OFFSET (TLS13_SESSION_ID_LEN + TLS13_CIPHERSUITE_LEN + TLS13_COMPRESSIONMETHD_LEN)

typedef enum {
   TLS13_CHANGE_CIPHERSPEC_RECORD = 0x14,
   TLS13_ALERT_RECORD             = 0x15,
   TLS13_HANDSHAKE_RECORD         = 0x16,
   TLS13_APPDATA_RECORD           = 0x17
   //TLS13_HEARTBEAT_RECORD         = 0x18
}tls13_recordType_e;

typedef enum {
   TLS13_HST_CLIENT_HELLO       = 0x01,
   TLS13_HST_SERVER_HELLO       = 0x02,
   TLS13_HST_NEW_SESSION_TICKET = 0x04,
   TLS13_HST_ENCRYPTED_EXT      = 0x08,
   TLS13_HST_CERTIFICATE        = 0x0B,
   TLS13_HST_SERVER_KEY_XCHNGE  = 0x0C,
   TLS13_HST_SERVER_HELLO_DONE  = 0x0E,
   TLS13_HST_CERTIFICATE_VERIFY = 0x0F,
   TLS13_HST_CLIENT_KEY_XCHNGE  = 0x10,
   TLS13_HST_FINISHED           = 0x14,
   TLS13_HST_END_OF_EARLY_DATA,
   TLS13_HST_CERTIFICATE_REQUEST,
   TLS13_HST_KEY_UPDATE
}tls13_handshakeType_e;

/* Handshake header declaration pseudocode in https://datatracker.ietf.org/doc/html/rfc8446#page-122
struct {
   tls13_handshakeType_e type;
   uint32_t length;
   select(tls13_handshakeHdr_t.type){
      case TLS13_HST_CLIENT_HELLO:          ClientHello;
      case TLS13_HST_SERVER_HELLO:          ServerHello;
      case TLS13_HST_END_OF_EARLY_DATA:     EndOfEarlyData;
      case TLS13_HST_ENCRYPTED_EXT:         EncryptedExtensions;
      case TLS13_HST_CERTIFICATE_REQUEST:   CertificateRequest;
      case TLS13_HST_CERTIFICATE:           Certificate;
      case TLS13_HST_CERTIFICATE_VERIFY:    CertificateVerify;
      case TLS13_HST_FINISHED:              Finished;
      case TLS13_HST_NEW_SESSION_TICKET:    NewSessionTicket;
      case TLS13_HST_KEY_UPDATE:            KeyUpdate;
   };
}tls13_handshakeHdr_t;
*/

typedef enum {
   TLS13_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF,
   TLS13_AES_128_GCM_SHA256            = 0x1301,
   TLS13_AES_256_GCM_SHA384            = 0x1302,
   TLS13_CHACHA20_POLY1305_SHA256      = 0x1303
}tls13_cipherSuite_e;

typedef enum {
   TLS13_ALERT_WARNING = 1,
   TLS13_ALERT_FATAL   = 2
}tls13_alertLevel_e;

typedef enum {
   TLS13_ALERT_CLOSE_NOTIFY          = 0,
   TLS13_UNEXPECTED_MESSAGE          = 10,
   TLS13_BAD_RECORD_MAC              = 20,
   TLS13_DECRYPTION_FAILED_RESERVED  = 21,
   TLS13_RECORD_OVERFLOW             = 22,
   TLS13_DECOMPRESSION_FAILURE       = 30,
   TLS13_HANDSHAKE_FAILURE           = 40,
   TLS13_NO_CERTIFICATE_RESERVED     = 41,
   TLS13_BAD_CERTIFICATE             = 42,
   TLS13_UNSUPPORTED_CERTIFICATE     = 43,
   TLS13_CERTIFICATE_REVOKED         = 44,
   TLS13_CERTIFICATE_EXPIRED         = 45,
   TLS13_CERTIFICATE_UNKNOWN         = 46,
   TLS13_ILLEGAL_PARAMETER           = 47,
   TLS13_UNKNOWN_CA                  = 48,
   TLS13_ACCESS_DENIED               = 49,
   TLS13_DECODE_ERROR                = 50,
   TLS13_DECRYPT_ERROR               = 51,
   TLS13_EXPORT_RESTRICTION_RESERVED = 60,
   TLS13_PROTOCOL_VERSION            = 70,
   TLS13_INSUFFICIENT_SECURITY       = 71,
   TLS13_INTERNAL_ERROR              = 80,
   TLS13_USER_CANCELED               = 90,
   TLS13_NO_RENEGOTIATION            = 100,
   TLS13_UNSUPPORTED_EXTENSION       = 110
} tls13_alertDescription_e;

#pragma pack(push, 1)

typedef struct {
   tls13_alertLevel_e level;
   tls13_alertDescription_e description;
} tls13_alert_t;

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
   uint8_t                    sessionId[0];               /* Session Id - usually fake */
   uint16_t                   cipherSuiteLen;
   tls13_cipherSuiteData_t    cipherSuiteList[0];         /* N_CIPHER_SUITE_SUPPORTED  */
   uint8_t                    compressionMethodLen;
   tls13_compressionMethods_t compressionMethodList[0];   /* N_COMPRESSION_METHOD_SUPPORTED         */
   uint16_t                   extLen;
   tls13_clientExtensions_t   clientExt;
} tls13_clientHello_t;

typedef struct{
   uint16_t                   cipherSuiteLen;
   tls13_cipherSuiteData_t    *cipherSuiteList;         /* N_CIPHER_SUITE_SUPPORTED  */
   uint8_t                    compressionMethodLen;
   tls13_compressionMethods_t *compressionMethodList;   /* N_COMPRESSION_METHOD_SUPPORTED         */
   uint16_t                    hostnameLen;
   uint8_t                    *hostname;
   uint8_t                    ecFormatsLen;
   uint8_t                    *ecPoints;
   uint8_t                    supportedGrpLen;
   uint16_t                   *supportedGrp;
   uint8_t                    sessTktLen;
   uint16_t                   *sessTkt;
   uint8_t                    eTMLen;
   uint16_t                   *eTM; /* Encrypt-then-MAC */
   uint8_t                    extMasterSecretLen;
   uint16_t                   *extMasterSecret;
   uint16_t                   signAlgoLen;
   uint16_t                   *signAlgos;
   uint16_t                   supportedVersionLen;
   uint16_t                   *supportedVersions;
   uint8_t                    keyXchangeModesLen;
   uint8_t                    *keyXchangeModes;
}tls13_capability_t;

/* Server Hello Extensions */
typedef struct{
   tls13_extension222_t       extSupportedVers;
   tls13_extensionKeyShare_t  extkeyShare;
}tls13_serverExtensions_t;

typedef struct{
    tls13_recordHdr_t         recordHeader;
    tls13_handshakeHdr_t      handshakeHeader;
    uint16_t                  serverVersion;            /* Server version - is usually the protocol version */
    uint8_t                   serverRandom[32];         /* server random - 32Bytes */
    uint8_t                   sessionIdLen;             /* Optional */
    uint8_t                   sessionId[0];               /* usually fake */
    uint16_t                  cipherSuiteSelect;
    uint8_t                   compressionMethodSelect;
    uint16_t                  extLen;
    tls13_serverExtensions_t  serverExt;
} tls13_serverHello_t;

typedef struct {
   tls13_handshakeHdr_t  handshakeHdr;
   uint16_t              extLen;
   uint16_t              extList[0]; // Need to check
   uint8_t               recordType;
}tls13_encryExt_t;

typedef struct {
   tls13_recordHdr_t     recordHeader;       /* 0x17 (application data) */
   uint8_t               encryptedData[0];   /* Data encrypted with the server handshake key */
   uint8_t               authTag[16];        /* AEAD authentication tag */
}tls13_wrappedRecord_t;

typedef struct {
   tls13_recordHdr_t     recordHeader;       /* 0x15 (TLS13_ALERT_RECORD) */ 
   tls13_alert_t         alert;
   uint8_t               authTag[16];        /* AEAD authentication tag */
}tls13_wrappedAlertRecord_t;

typedef struct {
   tls13_encryExt_t      encryExt;         /* could be Server Certificate  (tls13_serverCert_t) [or] server cert verify [or]  server finished [or] client finished */
   uint8_t               recordType;       /* 0x16 (handshake record); 0x17 (application data)*/   
}tls13_wrappedRecordDataDecrypt_t;

/* server & client change cipher spec - for compatability */
typedef struct{
   tls13_recordHdr_t     recordHeader;
   uint8_t               payload;       /* 1 Byte payload usually 0x01 */
}tls13_changeCipherSpec_t;

/* This structure includes change cipher Spec and encrypted data */
typedef struct {
   tls13_serverHello_t             serverHello;
   tls13_changeCipherSpec_t        serverCCS;
   tls13_wrappedRecord_t           record1;
}tls13_serverHellowCompat_t;

typedef struct {
   uint32_t     certLen : 24;
   uint8_t      cert[0];
   uint16_t     certExtLen;
#if CERT_EXT_SUPPORTED
   uint16_t     certExtension[0];
#endif
}tls13_cert_t;

typedef struct {
   tls13_handshakeHdr_t handshakeHdr;     /*  type 0x0B (certificate) */
   uint8_t              requestContext;
   uint32_t             payloadLen : 24;
   tls13_cert_t         cert[0];
}tls13_serverCert_t;

/* Certificate record */
typedef struct {
   tls13_recordHdr_t    recordHeader;     /* 0x17 (application data) */
   uint8_t              encryptedData[0];   /* Data encrypted with the server handshake key */
   uint8_t              authTag[16];      /* AEAD authentication tag */
}tls13_certRecord_t;

typedef struct {
   tls13_serverCert_t   certificate;      /* could be Server Certificate  (tls13_serverCert_t) */
   uint8_t              recordType;       /* 0x16 (handshake record) */   
}tls13_certRecordDataDecrypt_t;

typedef struct {
   uint16_t    signType;
   uint16_t    signLen;
   uint8_t     sign[0];
}tls13_signature_t;

typedef struct {
   tls13_handshakeHdr_t       handshakeHdr;    /* 0x0f (certificate verify) */
   tls13_signature_t          sign;
}tls13_serverCertVerify_t;

/* Certificate verify record */
typedef struct {   
   tls13_recordHdr_t          recordHeader;     /* 0x17 (application data) */
   uint8_t                    encryptedData[0]; /* Data encrypted with the server handshake key */
   uint8_t                    authTag[16];      /* AEAD authentication tag */
}tls13_certVerifyRecord_t;

typedef struct {
   tls13_serverCertVerify_t   certVerify;       /* server cert verify */
   uint8_t                    recordType;       /* 0x16 (handshake record) */    
}tls13_certVerifyRecordDataDecrypt_t;

typedef struct {
   tls13_handshakeHdr_t       handshakeHdr;    /* handshake message type 0x14 (finished) */
   uint8_t                    verifyData[0];
}tls13_finished_t;

/* Finished record */
typedef struct {
   tls13_recordHdr_t          recordHeader;     /* 0x17 (application data) */
   uint8_t                    encryptedData[0]; /* Data encrypted with the server handshake key */
   uint8_t                    authTag[16];      /* AEAD authentication tag */
}tls13_finishedRecord_t;

typedef struct {
   tls13_finished_t           finished;         /* server finished  */
uint8_t                    recordType;       /* 0x16 (handshake record) */
}tsl13_finishedRecordDataDecrypted_t;

typedef struct {
   tls13_finished_t           finished;         /* server finished  */
   uint8_t                    recordType;       /* 0x16 (handshake record) */
}tsl13_finishedClientRecordDataDecrypted_t;

/* Application data */
typedef struct {
   tls13_recordHdr_t          recordHeader;     /* 0x17 (application data) */
   uint8_t                    encryptedData[0];   /* Data encrypted with the server handshake key */
   uint8_t                    authTag[16];      /* AEAD authentication tag */
}tls13_appDataRecord_t;

typedef struct {
   tls13_certRecord_t         certRecord;
   tls13_certVerifyRecord_t   certVerifyRecord; 
   tls13_finishedRecord_t     finishedRecord;
}tls13_serverWrappedRecord_t;

typedef struct {
   tls13_changeCipherSpec_t   clientCCS;
   tls13_finishedRecord_t     finishedRecord;
   tls13_appDataRecord_t      appDataRecord;
}tls13_clientWrappedRecord_t;

typedef struct {
   tls13_handshakeHdr_t       handshakeHdr; /*  0x04 (new session ticket */
   uint32_t                   ticketLifetime;
   uint32_t                   ticketAgeAdd;
   uint8_t                    nounceLen;
   uint8_t                    nounce[0];
   uint16_t                   sessionTicketLen;
   uint8_t                    sessionTicket[0];
   uint16_t                   ticketExtensionLen;
   tls13_extension2222_t      extList[0];
}tls13_serverNewSesTkt_t;

typedef struct {
   tls13_recordHdr_t          recordHeader;     /* 0x17 (application data) */
   uint8_t                    encryptedData[0]; /* Data encrypted with the server handshake key */
   uint8_t                    authTag[16];      /* AEAD authentication tag */
}tls13_serverSesTktWrappedRecord_t;

typedef struct {
   tls13_serverNewSesTkt_t    sessionTicket;    /* session ticket  */
   uint8_t                    recordType;       /* 0x16 (handshake record) */
}tsl13_serverSesTktDataDecrypt_t;

#pragma pack(pop)

/* Macros for Structure element access */

#define CLIENTHELLO_CIPHERSUITE_LEN(clientHelloPtr, sessionIdLen)         \
               (*(uint16_t *)((&(((tls13_clientHello_t *)clientHelloPtr)->cipherSuiteLen) + (sessionIdLen/2))))

#define GET_CLIENTHELLO_CIPHERSUITELIST_PTR(clientHelloPtr, sessionIdLen)         \
                      ((&clientHelloPtr->cipherSuiteList[0]) + (sessionIdLen/2))
               //(tls13_cipherSuiteData_t *)((&(((tls13_clientHello_t *)clientHelloPtr)->cipherSuiteList) + sessionIdLen))

#define CLIENTHELLO_CMPMTHDLIST_LEN(clientHelloPtr, sessionIdLen, cipherSuiteLen)      \
               (*(((uint8_t *)&((tls13_clientHello_t *)clientHelloPtr)->compressionMethodLen) + sessionIdLen + cipherSuiteLen))

#define GET_CLIENTHELLO_CMPMTHDLIST_PTR(clientHelloPtr, sessionIdLen, cipherSuiteLen)      \
                  ((uint8_t *)(&clientHelloPtr->compressionMethodList[0]) + (sessionIdLen) + (cipherSuiteLen))
               //(tls13_compressionMethods_t *)((&(((tls13_clientHello_t *)clientHelloPtr)->compressionMethodList) + sessionIdLen + cipherSuiteLen))

//#define CLIENTHELLO_CLIENTEXT_LEN(clientHelloPtr, sessionIdLen, cipherSuiteLen, cmpMthdLen)      \
               (*(uint16_t *)((&((tls13_clientHello_t *)clientHelloPtr)->extLen) + sessionIdLen + cipherSuiteLen + cmpMthdLen))

#define GET_CLIENTHELLO_CLIENTEXT_PTR(clientHelloPtr, sessionIdLen, cipherSuiteLen, cmpMthdLen)      \
                  (tls13_clientExtensions_t *)((uint8_t *)(&clientHelloPtr->clientExt) + (sessionIdLen) + (cipherSuiteLen) + (cmpMthdLen))
               //(tls13_clientExtensions_t *)((&(((tls13_clientHello_t *)clientHelloPtr)->clientExt) + (sessionIdLen) + (cipherSuiteLen/2) + cmpMthdLen))

#define SERVERHELLO_CIPHERSUITE_SELECT(serverHelloPtr, sessionIdLen)         \
               (*(uint16_t *)((uint8_t *)(serverHelloPtr) + sessionIdLen))         

#define SERVERHELLO_COMPRESSION_METHOD_SELECT(serverHelloPtr, sessionIdLen)         \
               (*(uint8_t *)((uint8_t *)(serverHelloPtr) + sessionIdLen))
               
#define GET_SERVERHELLO_SERVEREXT_PTR(serverHelloPtr, sessionIdLen)         \
               (tls13_serverExtensions_t *)((uint8_t *)(serverHelloPtr) + sessionIdLen)

#define SERVERHELLO_SERVEREXT_LEN(serverHelloPtr, sessionIdLen)         \
               (*(uint16_t *)((uint8_t *)(serverHelloPtr.extLen) + sessionIdLen))

#define REACH_ELEMENT(inPtr, inPtrType, element, offset, retType)         \
               (*(retType *)((uint8_t *)&(((inPtrType *)inPtr)->element) + offset))

/* Prepare pkts to be sent  */
uint16_t tls13_prepareClientHello(const uint8_t *clientRandom, const uint8_t *sessionId, const char *dnsHostname, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, uint8_t *tlsPkt);

uint16_t tls13_prepareServerHello(const uint8_t *serverRandom, const uint8_t *sessionId, const tls13_cipherSuite_e cipherSuite, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, const uint16_t keyType, const uint8_t *extData, const uint16_t extDataLen, 
                                    uint8_t *tlsPkt);

uint16_t tls13_prepareServerWrappedRecord(const uint8_t *dCert, const uint16_t dCertLen,
                                        const uint8_t *dCertVerf, const uint16_t dCertVerfLen, 
                                        const uint8_t *dVerify, const uint16_t dVerifyLen, tls13_cipherSuite_e cs, 
                                        tls13_signAlgos_e signType, uint8_t *tlsPkt);

uint16_t tls13_prepareClientWrappedRecord(const uint8_t *dVerify, const uint16_t dVerifyLen,
                                            const uint8_t *appData, const uint8_t appDataLen, tls13_cipherSuite_e cs, uint8_t *tlsPkt);

uint16_t tls13_prepareServerSessionTicketRecord(const uint8_t *sessionTkt, \
                                                const uint8_t sessionTktLen, \
                                                tls13_cipherSuite_e cs, \
                                                uint8_t *tlsPkt);

uint16_t tls13_prepareAppData(const uint8_t *dIn, const uint16_t dInLen, tls13_cipherSuite_e cs, uint8_t *tlsPkt);

uint16_t tls13_prepareAlertRecord(const tls13_alert_t *alertData, tls13_cipherSuite_e cs, uint8_t *tlsPkt);

/* Deserialize and update data structures based on received pkts */

void tls13_extractClientHello(uint8_t *clientRandom, uint8_t *sessionId, uint8_t *dnsHostname, tls13_capability_t *capability,
                                    uint16_t *keyType, uint8_t *pubKey, uint16_t *pubKeyLen, const uint8_t *tlsPkt);

void tls13_extractServerHello(uint8_t *serverRandom, uint8_t *sessionId, uint16_t *cipherSuite, 
                                    uint8_t *pubKey, uint16_t *pubKeyLen, uint16_t *keyType, uint8_t *encryExt, uint16_t *encryExtLen, const uint8_t *tlsPkt);

void tls13_extractServerWrappedRecord(const uint8_t *tlsPkt, uint8_t *dCert, uint16_t *dCertLen, tls13_signature_t *sign, uint8_t *dVerify, uint16_t *dVerifyLen,
                                           tls13_cipherSuite_e cs, tls13_signAlgos_e signType);

void tls13_extractClientWrappedRecord(const uint8_t *tlsPkt, uint8_t *dVerify, uint16_t *dVerifyLen, uint8_t *appData, \
                                            uint16_t *appDataLen, tls13_cipherSuite_e cs);

void tls13_extractSessionTicket(tls13_serverNewSesTkt_t *sessionTkt, tls13_cipherSuite_e cs, const uint8_t *tlsPkt);

void tls13_extractEncryptedAppData(uint8_t *dOut, uint16_t *dOutLen, tls13_cipherSuite_e cs, const uint8_t *tlsPkt);

void tls13_extractAlertRecord(tls13_alert_t *alertData, tls13_cipherSuite_e cs, const uint8_t *tlsPkt);

/* utilities */
uint16_t tls13_htons(uint16_t dIn);

uint32_t tls13_htonss(uint32_t dIn);

uint32_t tls13_htonl(uint32_t dIn);

uint64_t tls13_htonll(uint64_t dIn);

uint16_t tls13_ntohs(uint16_t dIn);

uint32_t tls13_ntohss(uint32_t dIn);

uint32_t tls13_ntohl(uint32_t dIn);

uint64_t tls13_ntohll(uint64_t dIn);

#endif