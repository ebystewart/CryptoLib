#include <stdlib.h>
#include <string.h>
#include "tls13.h"
#include "math.h"


uint16_t tls13_prepareClientHello(tls13_clientHello_t *clientHello)
{
    tls13_clientHello_t *clientHelloTmp = calloc(1, sizeof(tls13_clientHello_t) + 200);

    /* Record header update */
    clientHelloTmp->recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    clientHelloTmp->recordHeader.protoVersion = TLS13_PROTO_VERSION;

    /* handshake header update */
    clientHelloTmp->handshakeHeader.handshakeType = TLS13_HST_CLIENT_HELLO;

    clientHelloTmp->clientVersion = TLS13_PROTO_VERSION;
    /* get a 32 Byte random value */
    //clientHelloTmp->clientRandom =
    memset(clientHelloTmp->clientRandom, 0x55, TLS13_RANDOM_LEN);
    clientHelloTmp->sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Get a 16 Byte Session Id */
    //clientHelloTmp->sessionId =
    memset(clientHelloTmp->sessionId, 0xAA, TLS13_SESSION_ID_LEN);

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
            strcpy(sniSub->listData, "dns.google.com");

            sniSub->listLen = strlen("dns.google.com"); // to be update
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
            memset(keyS->pubKey, 0xAB, 32);
            keyS->keyShareLen = 2; /* 2 Bytes of key share Type code */
            keyS->pubKeyLen = 32;  /* 32  Bytes of public key */
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
    memcpy((uint8_t *)clientHello, (uint8_t *)clientHelloTmp, (clientHelloTmp->recordHeader.recordLen + 1));
    free(clientHelloTmp);

    return (clientHello->recordHeader.recordLen + 1);
}

uint16_t tls13_prepareServerHello(tls13_serverHellowCompat_t *serverHello)
{
    tls13_serverHellowCompat_t *serverHelloTmp = calloc(1, sizeof(tls13_serverHellowCompat_t) + 200);

    /* Record header update */
    serverHelloTmp->serverHello.recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    serverHelloTmp->serverHello.recordHeader.protoVersion = TLS13_PROTO_VERSION;

    /* handshake header update */
    serverHelloTmp->serverHello.handshakeHeader.handshakeType = TLS13_HST_SERVER_HELLO;

    serverHelloTmp->serverHello.serverVersion = TLS13_PROTO_VERSION;
    /* get a 32 Byte random value */
    memset(&serverHelloTmp->serverHello.serverRandom, 0x55, TLS13_RANDOM_LEN);
    serverHelloTmp->serverHello.sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Get a 16 Byte Session Id */
    memset(&serverHelloTmp->serverHello.sessionId, 0xAA, TLS13_SESSION_ID_LEN);

    /* copy the Ciphersuite selected */
    serverHelloTmp->serverHello.cipherSuiteSelect = TLS13_AES_128_GCM_SHA256;

    /* copy the compression methods */
    SERVERHELLO_CIPHERSUITE_SELECT(&serverHelloTmp->serverHello, TLS13_SESSION_ID_LEN) = 0x00;

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
            memset(eKS->pubKey, 0xAB, 32);
            eKS->keyShareLen = 2; /* 2 Bytes of key share Type code */
            eKS->pubKeyLen = 32;  /* 32  Bytes of public key */
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

    rec->encryExt.handshakeHdr.handshakeType = TLS13_HST_ENCRYPTED_EXT;
    // Empty rec->encryExt.extList
    rec->encryExt.extLen = 0x0000;
    rec->encryExt.handshakeHdr.handshakeMsgLen = 2;

    rec->recordType = TLS13_HANDSHAKE_RECORD;

    /* Finally do a mem copy */
    memcpy((uint8_t *)serverHello, (uint8_t *)serverHelloTmp, (serverHelloTmp->serverHello.recordHeader.recordLen + 1 + \
                                                                sCCS->recordHeader.recordLen + 1 + \
                                                                rec->recordHeader.recordLen + 1 + \
                                                                rec->encryExt.handshakeHdr.handshakeMsgLen + 1 + 1));
    free(serverHelloTmp);

    return (serverHelloTmp->serverHello.recordHeader.recordLen + 1);
}

uint16_t tls13_prepareServerWrappedRecord(tls13_serverWrappedRecord_t *serverWrappedRecord)
{
    uint32_t len = 0;
    tls13_serverWrappedRecord_t *record = calloc(1, (sizeof(tls13_serverWrappedRecord_t) + 1200));

    tls13_certRecord_t *certRecord = &record->certRecord;
    {
        certRecord->recordHeader.recordType = TLS13_APPDATA_RECORD;
        certRecord->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
        memset(&certRecord->encryptedData, 0xBB, 123);  // encrypted data length to be standardised. data encrypted with the server handshake key
        memset(certRecord->authTag + 123, 0xFF, 16);

        /* Certificate details */
        certRecord->certificate.handshakeHdr.handshakeType = TLS13_HST_CERTIFICATE;
        certRecord->certificate.requestContext = 0x00;
        certRecord->certificate.payloadLen = 321 + 3 + sizeof(certRecord->certificate.cert->certExtension);
        certRecord->certificate.cert->certLen = 321;
        memset(&certRecord->certificate.cert->cert + 123, 0x9A, 321);
        certRecord->certificate.cert->certExtension = 0x0000;
        certRecord->certificate.handshakeHdr.handshakeMsgLen = certRecord->certificate.payloadLen + 3 + \
                                                               sizeof(certRecord->certificate.requestContext);

        certRecord->recordHeader.recordLen = certRecord->certificate.handshakeHdr.handshakeMsgLen + 1 + 123 + sizeof(certRecord->authTag) + 1;
        certRecord->recordType = TLS13_HANDSHAKE_RECORD;
        len += certRecord->recordHeader.recordLen + 1;
    }
    tls13_certVerifyRecord_t *certVerifyRecord = &record->certVerifyRecord + certRecord->recordHeader.recordLen + 1; 
    {
        certVerifyRecord->recordHeader.recordType = TLS13_APPDATA_RECORD;
        certVerifyRecord->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
        memset(&certVerifyRecord->encryptedData, 0xBB, 123);  // encrypted data length to be standardised. data encrypted with the server handshake key
        memset(certVerifyRecord->authTag + 123, 0xFF, 16);

        /* Certificate verification details */
        certVerifyRecord->certVerify.handshakeHdr.handshakeType = TLS13_HST_CERTIFICATE_VERIFY;
            certVerifyRecord->certVerify.sign.signType = 0x0804; /* reserved value for RSA-PSS-RSAE-SHA256 signature */
            certVerifyRecord->certVerify.sign.signLen = 111;
            memset(&certVerifyRecord->certVerify.sign.sign, 0xC8, 111);
        certVerifyRecord->certVerify.handshakeHdr.handshakeMsgLen = 111 + sizeof(certVerifyRecord->certVerify.sign.signLen) + 1;

        certVerifyRecord->recordHeader.recordLen = certVerifyRecord->certVerify.handshakeHdr.handshakeMsgLen + 16 + 123 + 1;
        certVerifyRecord->recordType = TLS13_HANDSHAKE_RECORD;

        len += certVerifyRecord->recordHeader.recordLen + 1;
    }
    tls13_finishedRecord_t *finishedRecord = &record->finishedRecord + certRecord->recordHeader.recordLen + 1 + certVerifyRecord->recordHeader.recordLen + 1;
    {
        finishedRecord->recordHeader.recordType = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
        memset(&finishedRecord->encryptedData, 0xBB, 123);  // encrypted data length to be standardised. data encrypted with the server handshake key
        memset(finishedRecord->authTag + 123, 0xFF, 16);

        /* Finished record details */
        finishedRecord->finished.handshakeHdr.handshakeType = TLS13_HST_FINISHED;
        memset(&finishedRecord->finished.verifyData, 0xFC, 50); // length should be revisted
        finishedRecord->finished.handshakeHdr.handshakeMsgLen = 50;
        
        finishedRecord->recordHeader.recordLen = finishedRecord->finished.handshakeHdr.handshakeMsgLen + 16 + 123 + 1;
        finishedRecord->recordType = TLS13_HANDSHAKE_RECORD;
        
        len += finishedRecord->recordHeader.recordLen + 1;
    }

    memcpy((uint8_t *)serverWrappedRecord, (uint8_t *)record, len);
    free(record);
}

uint16_t tls13_prepareClientWrappedRecord(tls13_clientWrappedRecord_t *clientWrappedRecord)
{
    uint32_t len = 0;
    tls13_clientWrappedRecord_t *record = calloc(1, (sizeof(tls13_clientWrappedRecord_t) + 1200));

    /* Fill and serialize the change cipher spec structure */
    tls13_changeCipherSpec_t *cCCS = &record->clientCCS;
    {
        cCCS->recordHeader.recordType   = TLS13_CHANGE_CIPHERSPEC_RECORD;
        cCCS->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
        cCCS->payload                   = 0x01;
        cCCS->recordHeader.recordLen    = 0x0001;
        len += cCCS->recordHeader.recordLen + 4;
    }
    tls13_finishedRecord_t *finishedRecord = &record->finishedRecord + len;
    {
        finishedRecord->recordHeader.recordType = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
        memset(&finishedRecord->encryptedData, 0xBB, 123);  // encrypted data length to be standardised. data encrypted with the server handshake key
        memset(finishedRecord->authTag + 123, 0xFF, 16);

        /* Finished record details */
        finishedRecord->finished.handshakeHdr.handshakeType = TLS13_HST_FINISHED;
        memset(&finishedRecord->finished.verifyData, 0xFC, 50); // length should be revisted
        finishedRecord->finished.handshakeHdr.handshakeMsgLen = 50;
        
        finishedRecord->recordHeader.recordLen = finishedRecord->finished.handshakeHdr.handshakeMsgLen + 16 + 123 + 1;
        finishedRecord->recordType = TLS13_HANDSHAKE_RECORD;
        
        len += finishedRecord->recordHeader.recordLen + 1;
    }
    tls13_appDataRecord_t *aDR = &record->appDataRecord + len;
    {
        aDR->recordHeader.recordType = TLS13_APPDATA_RECORD;
        aDR->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
        memset(&aDR->encryptedData, 0xBB, 5);    // encrypted data length to be standardised. data encrypted with the server handshake key
        memset(aDR->authTag + 5, 0xFF, 16);

        memset(&aDR->appData, 0x00, 10);

        aDR->recordHeader.recordLen = 10 + 16 + 5 + 1;
        aDR->recordType = TLS13_APPDATA_RECORD;
        
        len += aDR->recordHeader.recordLen + 1;
    }

    memcpy((uint8_t *)clientWrappedRecord, (uint8_t *)record, len);
    free(record);
}

uint16_t tls13_prepareServerSessionTicketRecord(tls13_serverSesTktWrappedRecord_t *sessionTicket)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_serverSesTktWrappedRecord_t *sNST = calloc(1, (sizeof(tls13_serverSesTktWrappedRecord_t) + 1200));

    sNST->recordHeader.recordType = TLS13_APPDATA_RECORD;
    sNST->recordHeader.protoVersion = 0x0303; /* Legacy TLS 1.2 */
    memset(&sNST->encryptedData, 0xBB, 100);    // encrypted data length to be standardised. data encrypted with the server handshake key
    offset += 100;
    memset(sNST->authTag + offset, 0xFF, 16);
    offset += 16;
    len = offset;

    tls13_serverNewSesTkt_t *sesTkt = &sNST->sessionTicket + offset;
    offset = 0; /* reusing variable */
    sesTkt->handshakeHdr.handshakeType = TLS13_HST_NEW_SESSION_TICKET;

    sesTkt->ticketLifetime = 0x012C;
    sesTkt->ticketAgeAdd = 0x0000;
    sesTkt->nounceLen  = 8;
    memset(&sesTkt->nounce, 0xDD, 8); /* 8 Bytes of nounce - length should come as argument */
    offset += 8;
    REACH_ELEMENT(sesTkt, tls13_serverNewSesTkt_t, sessionTicketLen, offset, uint16_t)  = 192; /* This also should come as argument */
    memset(&sesTkt->sessionTicket + offset, 0xAA, 192);
    offset += 192;
    REACH_ELEMENT(sesTkt, tls13_serverNewSesTkt_t, ticketExtensionLen, offset, uint16_t) = 0x0000;

    sesTkt->handshakeHdr.handshakeMsgLen = sizeof(sesTkt->ticketLifetime) + sizeof(sesTkt->ticketAgeAdd) + \
                                           sizeof(sesTkt->nounceLen) + sizeof(sesTkt->sessionTicketLen) + \
                                           sizeof(sesTkt->ticketExtensionLen) + offset;

    sNST->recordHeader.recordLen = len + sesTkt->handshakeHdr.handshakeMsgLen + 1 + 1;
    sNST->recordType = TLS13_APPDATA_RECORD;
        
    len = sNST->recordHeader.recordLen + 2 + 2 + 1;
    
    memcpy((uint8_t *)sNST, (uint8_t *)sessionTicket, len);

    free(sNST);
}