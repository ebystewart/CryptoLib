#ifndef _TLS13_H_
#define _TLS13_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct{
   /* 0x16 -> handshake record; 
      0x17 -> application data; 
      0x15 -> alert record 
   */ 
   uint8_t  recordType;
   uint16_t tlsVersion; /* 0x03 0x01 for TLS v1.3 */
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

typedef struct{
   uint16_t cipherSuiteCode;
}tls13_cipherSuiteData_t;

typedef struct{
   uint8_t compRessionMethodCode;
}tls13_compressionMethods_t;

/* Extension Type
   0x00 0x00 - Server Name
   0x00 0x05 - Status Request
   0x00 0x0A - Supported groups
   0x00 0x0B - EC Points format
   0x00 0x0D - Signature Algorithms
   0xff 0x01 - Renegotiation info
   0x00 0x12 - Signed Certificate Timestamp
   0x00 0x23 - Session Ticket
   0x00 0x16 - Encrypt-then-MAC
   0x00 0x17 - Extended Master Secret
   0x00 0x2B - Supported Versions
   0x00 0x2D - PSK Key exchange modes
   0x00 0x33 - Key Share
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
   uint8_t list[0];  // need seperate formatting of "server name" extension 
}tsl13_extension_t;

typedef struct{
   tls13_recordHdr_t          recordHeader;
   tls13_handshakeHdr_t       handshakeHeader;
   uint16_t                   version;                  /* Client version - is usually the protocol version */
   uint8_t                    clientRandom[32];         /* client random - 32Bytes */
   uint8_t                    sessionIdLen;             /* Optional */
   uint8_t                    sessionId[0];             /* usually fake */
   uint16_t                   cipherSuiteLen;
   tls13_cipherSuiteData_t    cipherSuiteList[0];       /* N_CIPHER_SUITE_SUPPORTED */
   uint8_t                    compressionMethodLength;
   tls13_compressionMethods_t compressionMethodList[0]; /* N_COMPRESSION_METHOD_SUPPORTED */
   uint16_t                   extensionLen;
   tsl13_extension_t          extensions[0];            /* N_EXTENSION_SUPPORTED */
} tls13_clientHello_t;

typedef struct{
    tls13_recordHdr_t    recordHeader;
    tls13_handshakeHdr_t handshakeHeader;
    uint16_t             version;                  /* Server version - is usually the protocol version */
    uint8_t              serverRandom[32];         /* server random - 32Bytes */
    uint8_t              sessionIdLen;             /* Optional */
    uint8_t              sessionId[0];             /* usually fake */
    uint16_t             cipherSuiteSelect;
    uint8_t              compressionMethodSelect;
    uint16_t             extensionLen;
    tsl13_extension_t    renegotiationInfo;
} tls13_serverHello_t;


#endif