#include <stdlib.h>
#include <string.h>
#include "tls13.h"
#include "math.h"


void tls13_prepareClientHello(tls13_clientHello_t *clientHello)
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
            tls13_extension2211_t *ecPF = &cExts->extECP;
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
}