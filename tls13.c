#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tls13.h"
#include "math.h"

/* ref: https://www.ietf.org/archive/id/draft-ietf-tls-rfc8446bis-03.html */
/*
       Client                                              Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*         -------->
                                                       ServerHello  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.
*/

static uint8_t authTagGlobal[TLS13_RECORD_AUTHTAG_LEN];

static bool tls13_verify_authTag(const uint8_t *authTag);

static void tls13_update_authTag(const uint8_t *authTag);

static bool tls13_verify_authTag(const uint8_t *authTag)
{
    bool retVal = false;

    retVal = (bool)memcmp(authTagGlobal, authTag, TLS13_RECORD_AUTHTAG_LEN);
    return retVal;
}

static void tls13_update_authTag(const uint8_t *authTag)
{
    memcpy(authTagGlobal, authTag, TLS13_RECORD_AUTHTAG_LEN);
}


/* Global Functions */
uint16_t tls13_prepareClientHello(const uint8_t *clientRandom, const uint8_t *sessionId, const uint8_t *dnsHostname, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, uint8_t *tlsPkt)
{
    uint16_t len = 0;
    tls13_clientHello_t *clientHelloTmp = calloc(1, sizeof(tls13_clientHello_t) + 200);

    /* Record header update */
    clientHelloTmp->recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    clientHelloTmp->recordHeader.protoVersion = TLS13_PROTO_VERSION;

    /* handshake header update */
    clientHelloTmp->handshakeHeader.handshakeType = TLS13_HST_CLIENT_HELLO;

    clientHelloTmp->clientVersion = TLS13_PROTO_VERSION;
    /* serialize the 32 Byte random value */
    //clientHelloTmp->clientRandom =
    memcpy(clientHelloTmp->clientRandom, clientRandom, TLS13_RANDOM_LEN);
    clientHelloTmp->sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Serialize the 16 Byte Session Id */
    //clientHelloTmp->sessionId =
    memcpy(clientHelloTmp->sessionId, sessionId, TLS13_SESSION_ID_LEN);

    /* copy the Ciphersuite data */
    CLIENTHELLO_CIPHERSUITE_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN) = TLS13_CIPHERSUITE_LEN;
    tls13_cipherSuiteData_t *csd = GET_CLIENTHELLO_CIPHERSUITELIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN);
    csd[0] = TLS13_AES_128_GCM_SHA256;
    csd[1] = TLS13_AES_256_GCM_SHA384;
    csd[2] = TLS13_CHACHA20_POLY1305_SHA256;

    /* copy the compression methods */
    CLIENTHELLO_CMPMTHDLIST_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN) = 0x01;
    tls13_compressionMethods_t *cmpMthd = GET_CLIENTHELLO_CMPMTHDLIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN);
    cmpMthd[0] = 0x00;

    clientHelloTmp->extLen = 0;

    /* Set up the extensions */
    tls13_clientExtensions_t *cExts = GET_CLIENTHELLO_CLIENTEXT_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN, 1);
    {
        {
            /* Set up the SNI extension data */
            tls13_extensionSNI_t *extSni = &cExts->extSNI;
            extSni->extType = 0x0000;
            tls13_extSubList_t *sniSub = &extSni->list;
            sniSub->listType = 0x00; /* DNS Hostname */
            strcpy(sniSub->listData, dnsHostname); /* "dns.google.com" */

            sniSub->listLen = strlen(dnsHostname); // to be update
            extSni->subListSize = sniSub->listLen + 3; // to be updated
            extSni->extDataLen = extSni->subListSize + 2;  // to be updated
            clientHelloTmp->extLen += extSni->extDataLen + 1;
        }
        {
            /* Set the EC Point Formats extension data */
            tls13_extension2211_t *ecPF = &cExts->extECP + clientHelloTmp->extLen;
            ecPF->extType = TLS13_EXT_EC_POINTS_FORMAT;
            uint8_t *ecPFList = &ecPF->list;
            ecPFList[0] = TLS13_EC_POINT_UNCOMPRESSED;
            ecPFList[1] = TLS13_EC_POINT_ANSIX962_COMPRESSED_PRIME;
            ecPFList[2] = TLS13_EC_POINT_ANSIX962_COMPRESSED_CHAR2;
            ecPF->subListSize = 3;
            ecPF->extDataLen = ecPF->subListSize + 1;
            clientHelloTmp->extLen += ecPF->extDataLen + 1;
        }
        {
            /* Set the supported Group extension data */
            tls13_extension2222_t *supGr = &cExts->extSupprotedGrp;
            supGr->extType = TLS13_EXT_SUPPORTED_GROUPS;
            uint16_t *supGrList = &supGr->list;
            supGrList[0] = TLS13_SUPPGRP_X25519;
            supGrList[1] = TLS13_SUPPGRP_SECP256R1;
            supGrList[2] = TLS13_SUPPGRP_X448;
            supGrList[3] = TLS13_SUPPGRP_SECP521R1;
            supGrList[4] = TLS13_SUPPGRP_SECP384R1;
            supGrList[5] = TLS13_SUPPGRP_FFDHE2048;
            supGrList[6] = TLS13_SUPPGRP_FFDHE3072;
            supGrList[7] = TLS13_SUPPGRP_FFDHE4096;
            supGrList[8] = TLS13_SUPPGRP_FFDHE6144;
            supGrList[9] = TLS13_SUPPGRP_FFDHE8192;

            supGr->subListSize = 20; /* each entry of 2 Bytes */
            supGr->extDataLen = supGr->subListSize + 2;
            clientHelloTmp->extLen += supGr->extDataLen + 1;
        }
        {
            /* set the Session Ticket extension data */
            tls13_extensionNULL_t *sesTic = &cExts->extSessionTicket;
            sesTic->extType = TLS13_EXT_SESSION_TICKET;
            sesTic->extDataLen = 0x0000;
            clientHelloTmp->extLen += sesTic->extDataLen + 1;
        }
        {
        /* Set the Encrypt-Then-MAC extension data */
            tls13_extensionNULL_t *enTM = &cExts->extEncryptThenMAC;
            enTM->extType = TLS13_EXT_ENCRYPT_THEN_MAC;
            enTM->extDataLen = 0x0000;
            clientHelloTmp->extLen += enTM->extDataLen + 1;
        }
        {
            /* Set the extended MAC secret extension data */
            tls13_extensionNULL_t *extMS = &cExts->extExtendedMasterSecret;
            extMS->extType = TLS13_EXT_EXT_MASTER_SECRET;
            extMS->extDataLen = 0x0000;
            clientHelloTmp->extLen += extMS->extDataLen + 1;
        }
        {
            /* Set the Signature Algorithms Extension data */  
            tls13_extension2222_t *sigAlg = &cExts->extSignatureAlgos;
            sigAlg->extType = TLS13_EXT_SIGN_AGLORITHM;
            uint16_t *sigAlgList = &sigAlg->list;
            sigAlgList[0] = TLS13_SIGNALGOS_ECDSA_SECP256r1_SHA256;
            sigAlgList[0] = TLS13_SIGNALGOS_ECDSA_SECP384r1_SHA384;
            sigAlgList[0] = TLS13_SIGNALGOS_ECDSA_SECP521r1_SHA512;
            sigAlgList[0] = TLS13_SIGNALGOS_ED25519;
            sigAlgList[0] = TLS13_SIGNALGOS_ED448;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PSS_PSS_SHA256;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PSS_PSS_SHA384;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PSS_PSS_SHA512;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA384;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA512;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PKCS1_SHA256;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PKCS1_SHA384;
            sigAlgList[0] = TLS13_SIGNALGOS_RSA_PKCS1_SHA512;

            sigAlg->subListSize = 28;
            sigAlg->extDataLen = sigAlg->subListSize + 2;
            clientHelloTmp->extLen += sigAlg->extDataLen + 1;
        }
        {
            /* Set the supported versions extension data */
            tls13_extension2212_t *supVers = &cExts->extSupportedVers;
            supVers->extType = TLS13_EXT_SUPPORTED_VERSIONS;
            uint16_t *supVersList = &supVers->list;
            supVersList[0] = TLS13_PROTO_VERSION;

            supVers->subListSize = 2;
            supVers->extDataLen = supVers->subListSize + 1;
            clientHelloTmp->extLen += supVers->extDataLen + 1;
        }
        {
            /* Set the PSK Key exchange modes extension data */
            tls13_extension2211_t *pskKE = &cExts->extPSKExchangeModes;
            pskKE->extType = TLS13_EXT_PSK_KEYXCHANGE_MODES;
            uint8_t *pskKEList = &pskKE->list;
            pskKEList[0] = 1; /* 01 - assigned value for "PSK with (EC)DHE key establishment */

            pskKE->subListSize = 1;
            pskKE->extDataLen = pskKE->subListSize + 1;
            clientHelloTmp->extLen += pskKE->extDataLen + 1;
        }
        {
            /* Set the key share extension data */
            tls13_extensionKeyShare_t *keyS = &cExts->extkeyShare;
            keyS->extType = TLS13_EXT_KEY_SHARE;
            keyS->keyShareType = 0x001D; /* assigned value for x25519 (key exchange via curve25519) */
            memcpy(keyS->pubKey, pubKey, pubKeyLen);
            keyS->keyShareLen = 2; /* 2 Bytes of key share Type code */
            keyS->pubKeyLen = pubKeyLen;  /* 32  Bytes of public key */
            keyS->extDataLen = keyS->keyShareLen + keyS->pubKeyLen + sizeof(keyS->keyShareLen);
            clientHelloTmp->extLen += keyS->extDataLen + 1;
        }
    }

    CLIENTHELLO_CLIENTEXT_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN, 1) = 0; // to be updated
    clientHelloTmp->handshakeHeader.handshakeMsgLen = sizeof(clientHelloTmp->clientVersion) + \
                                                        sizeof(clientHelloTmp->clientRandom) + \
                                                        TLS13_SESSION_ID_LEN + 1 + \
                                                        TLS13_CIPHERSUITE_LEN + 2 + \
                                                        1 + 1 + \
                                                        clientHelloTmp->extLen;
    clientHelloTmp->recordHeader.recordLen = clientHelloTmp->handshakeHeader.handshakeMsgLen + sizeof(tls13_handshakeHdr_t);

    /* Finally do a memcopy */
    len = clientHelloTmp->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    memcpy(tlsPkt, (uint8_t *)clientHelloTmp, len);

    free(clientHelloTmp);

    return len;
}

uint16_t tls13_prepareServerHello(const uint8_t *serverRandom, const uint8_t *sessionId, const uint16_t cipherSuite, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, uint8_t *tlsPkt)
{
    uint16_t len = 0;
    tls13_serverHellowCompat_t *serverHelloTmp = calloc(1, sizeof(tls13_serverHellowCompat_t) + 1200);

    /* Record header update */
    serverHelloTmp->serverHello.recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    serverHelloTmp->serverHello.recordHeader.protoVersion = TLS13_PROTO_VERSION;

    /* handshake header update */
    serverHelloTmp->serverHello.handshakeHeader.handshakeType = TLS13_HST_SERVER_HELLO;

    serverHelloTmp->serverHello.serverVersion = TLS13_PROTO_VERSION;
    /* get a 32 Byte random value */
    memcpy(serverHelloTmp->serverHello.serverRandom, serverRandom, TLS13_RANDOM_LEN);
    serverHelloTmp->serverHello.sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Get a 16 Byte Session Id */
    memcpy(serverHelloTmp->serverHello.sessionId, sessionId, TLS13_SESSION_ID_LEN);

    /* copy the Ciphersuite selected */
    //serverHelloTmp->serverHello.cipherSuiteSelect = cipherSuite;//TLS13_AES_128_GCM_SHA256;
    SERVERHELLO_CIPHERSUITE_SELECT(&serverHelloTmp->serverHello, TLS13_SESSION_ID_LEN) = cipherSuite;
    /* copy the compression methods */
    SERVERHELLO_COMPRESSION_METHOD_SELECT(&serverHelloTmp->serverHello, TLS13_SESSION_ID_LEN) = 0;

    uint16_t extLen = 0;

    /* Server Hello Extensions */
    {
        tls13_serverExtensions_t *serverExts = GET_SERVERHELLO_SERVEREXT_PTR(&serverHelloTmp->serverHello, TLS13_SESSION_ID_LEN);
        {
            tls13_extension222_t  *eSV = &serverHelloTmp->serverHello.serverExt.extSupportedVers;
            eSV->extType = TLS13_EXT_SUPPORTED_VERSIONS;
            eSV->extData = TLS13_PROTO_VERSION;
            eSV->extDataLen = 2;
            extLen += eSV->extDataLen + 1;
        }
        {
            tls13_extensionKeyShare_t  *eKS = &serverHelloTmp->serverHello.serverExt.extkeyShare;
            eKS->extType = TLS13_EXT_KEY_SHARE;
            eKS->keyShareType = 0x001D; /* assigned value for x25519 (key exchange via curve25519) */
            memcpy(eKS->pubKey, pubKey, pubKeyLen);
            eKS->keyShareLen = 2; /* 2 Bytes of key share Type code */
            eKS->pubKeyLen = pubKeyLen;  /* 32  Bytes of public key */
            eKS->extDataLen = eKS->keyShareLen + eKS->pubKeyLen + sizeof(eKS->keyShareLen);
            extLen += eKS->extDataLen + 1;
        }
    }
    SERVERHELLO_SERVEREXT_LEN(&serverHelloTmp->serverHello, TLS13_SESSION_ID_LEN) = extLen;
    serverHelloTmp->serverHello.handshakeHeader.handshakeMsgLen = sizeof(serverHelloTmp->serverHello.serverVersion) + \
                                                        sizeof(serverHelloTmp->serverHello.serverRandom) + \
                                                        TLS13_SESSION_ID_LEN + 1 + \
                                                        2 + 1 + \
                                                        serverHelloTmp->serverHello.extLen;
    serverHelloTmp->serverHello.recordHeader.recordLen = serverHelloTmp->serverHello.handshakeHeader.handshakeMsgLen + sizeof(tls13_handshakeHdr_t);

    /* Fill and serialize the change cipher spec structure */
    tls13_changeCipherSpec_t *sCCS = &serverHelloTmp->serverCCS + serverHelloTmp->serverHello.recordHeader.recordLen;

    sCCS->recordHeader.recordType   = TLS13_CHANGE_CIPHERSPEC_RECORD;
    sCCS->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
    sCCS->payload                   = 0x01;
    sCCS->recordHeader.recordLen    = 0x0001;

    /* Fill and serialize the first wrapped record with encrypted data */
    tls13_wrappedRecord_t *rec = &serverHelloTmp->record1 + serverHelloTmp->serverHello.recordHeader.recordLen + sizeof(tls13_changeCipherSpec_t);

    rec->recordHeader.recordType = TLS13_APPDATA_RECORD;
    rec->recordHeader.protoVersion = 0x0303; /* legacy TLS 1.2 */
    memset(rec->encryptedData, 0xCC, 7);     /* encrypted data with server handshake key */
    memset(rec->authTag + 6, 0xFF, 16);      /* 16 Byte auth tag */
    rec->recordHeader.recordLen = 7 + 16;
#if 0
    rec->encryExt.handshakeHdr.handshakeType = TLS13_HST_ENCRYPTED_EXT;
    // Empty rec->encryExt.extList
    rec->encryExt.extLen = 0x0000;
    rec->encryExt.handshakeHdr.handshakeMsgLen = 2;

    rec->recordType = TLS13_HANDSHAKE_RECORD;
#endif
    len = serverHelloTmp->serverHello.recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE + \
                                                                sCCS->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE + \
                                                                rec->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    /* Finally do a memory copy */
    memcpy(tlsPkt, (uint8_t *)serverHelloTmp, len);
    free(serverHelloTmp);

    return len;
}

void tls13_extractServerHello(uint8_t *serverRandom, uint8_t *sessionId, uint16_t *cipherSuite, 
                                    uint8_t *pubKey, uint16_t *pubKeyLen, const uint8_t *tlsPkt)
{

}

uint16_t tls13_prepareServerWrappedRecord(const uint8_t *dCert, const uint16_t dCertLen, const uint8_t *authTag, 
                                        const uint8_t *dCertVerf, const uint16_t dCertVerfLen, 
                                        const uint8_t *dVerify, const uint16_t dVerifyLen, uint8_t *tlsPkt)
{
    uint32_t len = 0;
    uint16_t offset = 0;
    tls13_serverWrappedRecord_t *record = calloc(1, (sizeof(tls13_serverWrappedRecord_t) + 1200));

    tls13_certRecord_t *certRecord = &record->certRecord;
    {
        certRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        certRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        /* Encrypt the data before copying */
        memcpy(certRecord->encryptedData, dCert, dCertLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += dCertLen;
        memcpy(certRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        offset += TLS13_RECORD_AUTHTAG_LEN;  
        certRecord->recordHeader.recordLen = offset;
        /* Number of bytes so far */
        len += certRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    }
    offset = 0;
    tls13_certVerifyRecord_t *certVerifyRecord = &record->certVerifyRecord + len; 
    {
        certVerifyRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        certVerifyRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        /* Encrypt the data before copying */
        memcpy(certVerifyRecord->encryptedData, 0xBB, 123);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += dCertVerfLen;
        memcpy(certVerifyRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        offset += TLS13_RECORD_AUTHTAG_LEN;

        certVerifyRecord->recordHeader.recordLen = offset;
        /* Number of Bytes so far */
        len += certVerifyRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    }
    offset = 0;
    tls13_finishedRecord_t *finishedRecord = &record->finishedRecord + len;
    {
        finishedRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        /* Encrypt the data before copying */
        memcpy(&finishedRecord->encryptedData, dVerify, dVerifyLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += dVerifyLen;
        memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
     
        finishedRecord->recordHeader.recordLen = offset;
        /* NUmber of Bytes so far */
        len += finishedRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    }

    memcpy(tlsPkt, (uint8_t *)record, len);
    free(record);
    return len;
}

void tls13_extractServerWrappedRecord(const uint8_t *tlsPkt, tls13_cert_t *dCert, tls13_signature_t *sign, uint8_t *dVerify, uint16_t *dVerifyLen)
{
    uint16_t certLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t certVerfLen = ((uint16_t)tlsPkt[certLen + 3] << 8 | tlsPkt[certLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t verfLen = ((uint16_t)tlsPkt[certLen + certVerfLen + 3] << 8 | tlsPkt[certLen + certVerfLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tls13_serverWrappedRecord_t *tmp = calloc(1, certLen + certVerfLen + verfLen);

    if(tlsPkt[6] == TLS13_HST_CERTIFICATE){
        tls13_certRecord_t *recvdCertRecord = &tmp->certRecord;
        /* Some basic assertion to check for pkt deformity */
        assert(recvdCertRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdCertRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdCertRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);

        tls13_certRecordDataDecrypt_t *dCertTemp = &recvdCertRecord->encryptedData;
        assert(dCertTemp->recordType == TLS13_HANDSHAKE_RECORD);
        assert(dCertTemp->certificate.handshakeHdr.handshakeType == TLS13_HST_CERTIFICATE);

        dCert->certLen = dCertTemp->certificate.cert->certLen;
        if(dCert->cert != NULL)
            memcpy(dCert->cert, dCertTemp->certificate.cert->cert, dCert->certLen);
        dCert->certExtension = REACH_ELEMENT(dCertTemp->certificate.cert, tls13_cert_t, certExtension, dCert->certLen, uint16_t);
    }
    if(tlsPkt[6 + certLen] == TLS13_HST_CERTIFICATE_VERIFY)
    {
        tls13_certVerifyRecord_t *recvdCertVerifyRecord = &tmp->certVerifyRecord + certLen;
        assert(recvdCertVerifyRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdCertVerifyRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdCertVerifyRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        
        tls13_certVerifyRecordDataDecrypt_t *dSign = &recvdCertVerifyRecord->encryptedData;
        assert(dSign->recordType == TLS13_HANDSHAKE_RECORD);
        assert(dSign->certVerify.handshakeHdr.handshakeType == TLS13_HST_CERTIFICATE_VERIFY);

        sign->signType = dSign->certVerify.sign.signType;
        sign->signLen = dSign->certVerify.sign.signLen;
        if(sign->sign != NULL)
            memcpy(sign->sign, dSign->certVerify.sign.sign, sign->signLen);
    }
    if(tlsPkt[6 + certLen + certVerfLen] == TLS13_HST_FINISHED)
    {
        tls13_finishedRecord_t *recvdFinRecord = &tmp->finishedRecord + certLen + certVerfLen;
        assert(recvdFinRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdFinRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdFinRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);

        tsl13_finishedRecordDataDecrypted_t *verf = &recvdFinRecord->encryptedData;
        assert(verf->recordType == TLS13_HANDSHAKE_RECORD);
        assert(verf->finished.handshakeHdr.handshakeType == TLS13_HST_FINISHED);

        if(dVerify != NULL){
            memcpy(dVerify, verf->finished.verifyData, verfLen - TLS13_RECORD_HEADER_SIZE);
            *dVerifyLen = verfLen - TLS13_RECORD_HEADER_SIZE;
        }
    }      
    free(tmp);
}

uint16_t tls13_prepareClientWrappedRecord(const uint8_t *dVerify, const uint16_t dVerifyLen, const uint8_t *authTag, 
                                            const uint8_t *appData, const uint8_t appDataLen, uint8_t *tlsPkt)
{
    uint32_t len = 0;
    uint16_t offset = 0;
    tls13_clientWrappedRecord_t *record = calloc(1, (sizeof(tls13_clientWrappedRecord_t) + 1200));

    /* Fill and serialize the change cipher spec structure */
    tls13_changeCipherSpec_t *cCCS = &record->clientCCS;
    {
        cCCS->recordHeader.recordType   = TLS13_CHANGE_CIPHERSPEC_RECORD;
        cCCS->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        cCCS->payload                   = 0x01;
        cCCS->recordHeader.recordLen    = 0x0001;
        len += cCCS->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    }
    tls13_finishedRecord_t *finishedRecord = &record->finishedRecord + len;
    {
        finishedRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        /* Data to be encrypted before copying */
        memcpy(finishedRecord->encryptedData, dVerify, dVerifyLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += dVerifyLen;
        memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        offset += TLS13_RECORD_AUTHTAG_LEN;
     
        finishedRecord->recordHeader.recordLen = offset;
        len += finishedRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    }
    offset = 0;
    tls13_appDataRecord_t *aDR = &record->appDataRecord + len;
    {
        aDR->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        aDR->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        /* Data to be encrypted before copying */
        memcpy(aDR->encryptedData, appData, appDataLen);    // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += appDataLen;
        memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        offset += TLS13_RECORD_AUTHTAG_LEN;

        aDR->recordHeader.recordLen = offset + TLS13_RECORD_HEADER_SIZE; 
        len += aDR->recordHeader.recordLen;
    }

    memcpy(tlsPkt, (uint8_t *)record, len);
    free(record);
    return len;
}

void tls13_extractClientWrappedRecord(const uint8_t *tlsPkt, uint8_t *dVerify, uint16_t *dVerifyLen, uint8_t *appData, uint16_t *appDataLen)
{
    uint16_t ccspLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t verifLen = ((uint16_t)tlsPkt[ccspLen + 3] << 8 | tlsPkt[ccspLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t dataLen = ((uint16_t)tlsPkt[ccspLen + verifLen + 3] << 8 | tlsPkt[ccspLen + verifLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tls13_clientWrappedRecord_t *tmp = calloc(1, ccspLen + ccspLen + verifLen);

    if(tlsPkt[6] == TLS13_HST_FINISHED)
    {
        tls13_changeCipherSpec_t *recvdChangeCipherSpec = &tmp->clientCCS;
        /* Verify the auth Tag */

        assert(recvdChangeCipherSpec->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdChangeCipherSpec->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdChangeCipherSpec->recordHeader.protoVersion == TLS13_PROTO_VERSION);

        /* Ignore the payload */
        assert(recvdChangeCipherSpec->payload == 1);
    }  

    if(tlsPkt[6 + ccspLen] == TLS13_HST_FINISHED)
    {
        tls13_finishedRecord_t *recvdFinRecord = &tmp->finishedRecord + ccspLen;
        assert(recvdFinRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdFinRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdFinRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        /* Verify the auth Tag */
        tsl13_finishedRecordDataDecrypted_t *verf = &recvdFinRecord->encryptedData;
        assert(verf->recordType == TLS13_HANDSHAKE_RECORD);
        assert(verf->finished.handshakeHdr.handshakeType == TLS13_HST_FINISHED);

        if(dVerify != NULL){
            memcpy(dVerify, verf->finished.verifyData, verifLen - TLS13_RECORD_HEADER_SIZE); // decrypt before copying 
            *dVerifyLen = verifLen - TLS13_RECORD_HEADER_SIZE;
        }
    }
    if(tlsPkt[6 + ccspLen + verifLen] == TLS13_HST_FINISHED)
    {
        tls13_appDataRecord_t *recvdAppData = &tmp->appDataRecord + ccspLen + verifLen;
        /* Verify the auth Tag */
        assert(recvdAppData->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdAppData->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdAppData->recordHeader.protoVersion == TLS13_PROTO_VERSION);

        if(dVerify != NULL){
            memcpy(appData, recvdAppData->encryptedData, verifLen - TLS13_RECORD_HEADER_SIZE); // need to decrypt data before copying 
            *appDataLen = dataLen - TLS13_RECORD_HEADER_SIZE;
        }
    }      
    free(tmp);
}

uint16_t tls13_prepareServerSessionTicketRecord(const uint8_t *sessionTkt, const uint8_t sessionTktLen, const uint8_t *authTag, uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_serverSesTktWrappedRecord_t *sNST = calloc(1, (sizeof(tls13_serverSesTktWrappedRecord_t) + 1200));

    sNST->recordHeader.recordType = TLS13_APPDATA_RECORD;
    sNST->recordHeader.protoVersion = TLS12_PROTO_VERSION;      /* Legacy TLS 1.2 */
    memset(&sNST->encryptedData, sessionTkt, sessionTktLen);    // session ticket with the server handshake key
    offset += sessionTktLen;
    memset(sNST->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
    offset += TLS13_RECORD_AUTHTAG_LEN;

    sNST->recordHeader.recordLen = offset;
        
    len = sNST->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE; 
    memcpy(tlsPkt, (uint8_t *)sNST, len);
    free(sNST);
    return len;
}

void tls13_extractSessionTicket(tls13_serverNewSesTkt_t *sessionTkt, uint8_t *authTag, const uint8_t *tlsPkt)
{
    uint16_t dataSize = 0;
    uint16_t offset = 0;

    uint16_t pktLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    tls13_serverSesTktWrappedRecord_t *tmp = calloc(1, pktLen);
    memcpy((uint8_t *)tmp, tlsPkt, pktLen);

    /* Some basic assertion to check for pkt deformity */
    assert(tmp->recordHeader.recordType == TLS13_APPDATA_RECORD);
    assert(tmp->recordHeader.protoVersion == TLS12_PROTO_VERSION || tmp->recordHeader.protoVersion == TLS13_PROTO_VERSION);
    //assert((tmp->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE) == pktSize);

    dataSize = tmp->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
    memcpy(authTag, (tmp->authTag + dataSize), TLS13_RECORD_AUTHTAG_LEN);

    tsl13_serverSesTktDataDecrypt_t *tmp1 = &tmp->encryptedData;
    /* decrypt the data */
    assert(tmp1->recordType == TLS13_HANDSHAKE_RECORD);
    sessionTkt->handshakeHdr.handshakeType = tmp1->sessionTicket.handshakeHdr.handshakeType;
    sessionTkt->handshakeHdr.handshakeMsgLen = tmp1->sessionTicket.handshakeHdr.handshakeMsgLen;
    sessionTkt->ticketLifetime = 
    sessionTkt->ticketAgeAdd =

    sessionTkt->nounceLen = tmp1->sessionTicket.nounceLen;
    if(*sessionTkt->nounce != NULL)
        memcpy(sessionTkt->nounce, tmp1->sessionTicket.nounce, sessionTkt->nounceLen);
    offset += sessionTkt->nounceLen;

    //sessionTkt->sessionTicketLen = tmp1->sessionTicket.sessionTicketLen;
    sessionTkt->sessionTicketLen = REACH_ELEMENT(&tmp1->sessionTicket, tls13_serverNewSesTkt_t, sessionTicketLen, offset, uint8_t);
    if(*sessionTkt->sessionTicket != NULL)
        memcpy(sessionTkt->sessionTicket, tmp1->sessionTicket.nounce + offset, sessionTkt->sessionTicketLen);
    offset += sessionTkt->sessionTicketLen;

    //sessionTkt->ticketExtensionLen = tmp1->sessionTicket.ticketExtensionLen;
    sessionTkt->ticketExtensionLen = REACH_ELEMENT(&tmp1->sessionTicket, tls13_serverNewSesTkt_t, ticketExtensionLen, offset, uint16_t);
    if(sessionTkt->extList != NULL) 
        memcpy(sessionTkt->extList, &tmp1->sessionTicket.extList + offset, sessionTkt->ticketExtensionLen);
    free(tmp);
}

/* There should be a max cap to the dataLen. Data length should be inclusive of padding  */
/* TLS pkt is expected to be in little endian format */
uint16_t tls13_prepareAppData(const uint8_t *dIn, const uint16_t dInLen, const uint8_t *authTag, uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_appDataRecord_t *app = calloc(1, sizeof(tls13_appDataRecord_t));

    app->recordHeader.recordType   = TLS13_APPDATA_RECORD;
    app->recordHeader.protoVersion = TLS12_PROTO_VERSION;      /* Legacy TLS 1.2 */

    /* Need to encrypt data */
    memcpy(app->encryptedData, dIn, dInLen);    /* data encrypted with the server handshake key */
    offset += dInLen;

    memcpy(app->authTag, authTag, TLS13_RECORD_AUTHTAG_LEN);
    offset += TLS13_RECORD_AUTHTAG_LEN;

    app->recordHeader.recordLen = offset;      
    len = app->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;  
    memcpy(tlsPkt, (uint8_t *)app, len);
    free(app);

    return len;
}

void tls13_extractEncryptedAppData(uint8_t *dOut, uint16_t *dOutLen, uint8_t *authTag, const uint8_t *tlsPkt)
{
    uint16_t dataSize = 0;
    uint16_t pktLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    tls13_appDataRecord_t *tmp = calloc(1, pktLen);
    memcpy((uint8_t *)tmp, tlsPkt, pktLen);

    /* Some basic assertion to check for pkt deformity */
    assert(tmp->recordHeader.recordType == TLS13_APPDATA_RECORD);
    assert(tmp->recordHeader.protoVersion == TLS12_PROTO_VERSION || tmp->recordHeader.protoVersion == TLS13_PROTO_VERSION);
    //assert((tmp->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE) == pktLen);

    dataSize = tmp->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
    /* Need to decrypt the data before copying to buffer */
    memcpy(dOut, tmp->encryptedData, dataSize);
    *dOutLen = dataSize;

    memcpy(authTag, tmp->authTag, TLS13_RECORD_AUTHTAG_LEN);
    free(tmp);
}