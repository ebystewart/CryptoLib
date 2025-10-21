#ifndef _TLS13_EXTENSIONS_H_
#define _TLS13_EXTENSIONS_H_

#include <stdint.h>

/* Extension Type
   0x00 0x05 - Status Request
   0x00 0x0A - Supported groups
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

/* Signature Algorithms
   04 03 - assigned value for ECDSA-SECP256r1-SHA256
   05 03 - assigned value for ECDSA-SECP384r1-SHA384
   06 03 - assigned value for ECDSA-SECP521r1-SHA512
   08 07 - assigned value for ED25519
   08 08 - assigned value for ED448
   08 09 - assigned value for RSA-PSS-PSS-SHA256
   08 0a - assigned value for RSA-PSS-PSS-SHA384
   08 0b - assigned value for RSA-PSS-PSS-SHA512
   08 04 - assigned value for RSA-PSS-RSAE-SHA256
   08 05 - assigned value for RSA-PSS-RSAE-SHA384
   08 06 - assigned value for RSA-PSS-RSAE-SHA512
   04 01 - assigned value for RSA-PKCS1-SHA256
   05 01 - assigned value for RSA-PKCS1-SHA384
   06 01 - assigned value for RSA-PKCS1-SHA512
*/
typedef struct{
   uint16_t extType;
   uint16_t extDataLen;
   uint16_t subListSize;
   uint16_t list[0];
}tls13_extension2222_t;

typedef struct{
   uint8_t  listType;   /*  0x00 "DNS hostname" */
   uint16_t listLen;
   uint8_t  listData[0];
}tls13_extSubList_t;

/* Extension Type - Server Name Indication
   0x00 0x00 - Server Name
*/
typedef struct{
   uint16_t           extType;
   uint16_t           extDataLen;
   uint16_t           subListSize;
   tls13_extSubList_t list[0];
}tls13_extensionSNI_t;

/* Extension Type: EC Point Format
   0x00 0x0B - EC Points format
   0x00 0x2D - PSK Key exchange modes
*/
typedef struct{
   uint16_t extType;
   uint16_t extDataLen;
   uint8_t  subListSize;
   uint8_t  list[0];
}tls13_extension2211_t;

/* Extension Type: Supported Versions
   0x00 0x2B - Supported Versions
*/
typedef struct{
   uint16_t extType;
   uint16_t extDataLen;
   uint8_t  subListSize;
   uint16_t list[0];
}tls13_extension2212_t;

/* NULL extension entry 
   0x00 0x23 - Session Ticket
   0x00 0x16 - Encrypt-then-MAC
   0x00 0x17 - Extended Master Secret
*/
typedef struct{
   uint16_t extType;
   uint16_t extDataLen;
}tls13_extensionNULL_t;

/* Extension Type Key Share 
   00 33 - assigned value for extension "Key Share"
*/
typedef struct{
   uint16_t  extType;
   uint16_t  extDataLen;
   uint16_t  keyShareTypeLen;
   uint16_t  keyShareType;
   uint16_t  pubKeyLen;
   uint8_t   pubKey[0];
}tls13_extensionKeyShare_t;

/*
   00 2b - assigned value for extension "Supported Versions"
*/
typedef struct{
   uint16_t extType;
   uint16_t extDataLen;
   uint16_t extData;
}tls13_extension222_t;

#endif