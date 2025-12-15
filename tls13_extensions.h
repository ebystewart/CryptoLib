#ifndef _TLS13_EXTENSIONS_H_
#define _TLS13_EXTENSIONS_H_

#include <stdint.h>

typedef enum {
    TLS13_CLIENT,
    TLS13_SERVER
}tls13_ctxType_e;

typedef enum {
   TLS13_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF,
   TLS13_AES_128_GCM_SHA256            = 0x1301,
   TLS13_AES_256_GCM_SHA384            = 0x1302,
   TLS13_CHACHA20_POLY1305_SHA256      = 0x1303
}tls13_cipherSuite_e;

/* Extension Type
   0x00 0x05 - Status Request
   0x00 0x0A - Supported groups
   0x00 0x0D - Signature Algorithms
   0xff 0x01 - Renegotiation info
   0x00 0x12 - Signed Certificate Timestamp
*/
typedef enum {
   TLS13_EXT_SERVER_NAME          = 0x0000,
   TLS13_EXT_STATUS_REQUEST       = 0x0005,
   TLS13_EXT_SUPPORTED_GROUPS     = 0x000A,
   TLS13_EXT_EC_POINTS_FORMAT     = 0x000B,
   TLS13_EXT_SIGN_AGLORITHM       = 0x000D,
   TLS13_EXT_SIGN_CERT_TIMESTAMP  = 0x0012,
   TLS13_EXT_ENCRYPT_THEN_MAC     = 0x0016,
   TLS13_EXT_EXT_MASTER_SECRET    = 0x0017,   
   TLS13_EXT_PSK_KEYXCHANGE_MODES = 0x002D,
   TLS13_EXT_SUPPORTED_VERSIONS   = 0x002B,
   TLS13_EXT_SESSION_TICKET       = 0x0023,
   TLS13_EXT_KEY_SHARE            = 0x0033,
   TLS13_EXT_RENOGO_INFO          = 0xFF01
}tls13_extTyep_e;

/* Supported Groups
   00 1d - assigned value for the curve "x25519"
   00 17 - assigned value for the curve "secp256r1"
   00 1e - assigned value for the curve "x448"
   00 19 - assigned value for the curve "secp521r1"
   00 18 - assigned value for the curve "secp384r1"
   01 00 - assigned value for the curve "ffdhe2048"
   01 01 - assigned value for the curve "ffdhe3072"
   01 02 - assigned value for the curve "ffdhe4096"
   01 03 - assigned value for the curve "ffdhe6144"
   01 04 - assigned value for the curve "ffdhe8192"
*/
typedef enum {
   TLS13_SUPPGRP_X25519    = 0x001D,
   TLS13_SUPPGRP_SECP256R1 = 0x0017,
   TLS13_SUPPGRP_X448      = 0x001E,
   TLS13_SUPPGRP_SECP521R1 = 0x0019,
   TLS13_SUPPGRP_SECP384R1 = 0x0018,
   TLS13_SUPPGRP_FFDHE2048 = 0x0100,
   TLS13_SUPPGRP_FFDHE3072 = 0x0101,
   TLS13_SUPPGRP_FFDHE4096 = 0x0102,
   TLS13_SUPPGRP_FFDHE6144 = 0x0103,
   TLS13_SUPPGRP_FFDHE8192 = 0x0104
}tls13_supGroups_e;

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
typedef enum {
   TLS13_SIGNALGOS_ECDSA_SECP256r1_SHA256 = 0x0403,
   TLS13_SIGNALGOS_ECDSA_SECP384r1_SHA384 = 0x0503,
   TLS13_SIGNALGOS_ECDSA_SECP521r1_SHA512 = 0x0603,
   TLS13_SIGNALGOS_ED25519                = 0x0807,
   TLS13_SIGNALGOS_ED448                  = 0x0808,
   TLS13_SIGNALGOS_RSA_PSS_PSS_SHA256     = 0x0809,
   TLS13_SIGNALGOS_RSA_PSS_PSS_SHA384     = 0x080A,
   TLS13_SIGNALGOS_RSA_PSS_PSS_SHA512     = 0x080B,
   TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256    = 0x0804,
   TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA384    = 0x0805,
   TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA512    = 0x0806,
   TLS13_SIGNALGOS_RSA_PKCS1_SHA256       = 0x0401,
   TLS13_SIGNALGOS_RSA_PKCS1_SHA384       = 0x0501,
   TLS13_SIGNALGOS_RSA_PKCS1_SHA512       = 0x0601
}tls13_signAlgos_e;

/* EC Point formats
   00 - assigned value for format "uncompressed"
   01 - assigned value for format "ansiX962_compressed_prime"
   02 - assigned value for format "ansiX962_compressed_char2"
*/
typedef enum {
   TLS13_EC_POINT_UNCOMPRESSED = 0,
   TLS13_EC_POINT_ANSIX962_COMPRESSED_PRIME = 1,
   TLS13_EC_POINT_ANSIX962_COMPRESSED_CHAR2 = 2
}tls13_ecPointFormat_e;

/* Structures */
#pragma pack(push, 1)

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
   uint16_t  keyShareLen;
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

#pragma pack(pop)

#endif