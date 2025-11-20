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

/* Static function declarations */

static bool tls13_verify_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, const uint8_t *mac, const uint16_t macLen, tls13_cipherSuite_e cs);

static bool tls13_generate_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *mac, uint16_t macLen, tls13_cipherSuite_e cs);

static void tls13_encrypt(const uint8_t *plainText, const uint16_t plainTextLen, uint8_t *cipherText, tls13_cipherSuite_e cs);

static void tls13_decrypt(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *plainText, tls13_cipherSuite_e cs);

static tls13_cipherSuite_e tls13_getCipherSuite(void);

static tls13_signAlgos_e tls13_getSignatureType(void);


/* Static function definitions */

static bool tls13_verify_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, const uint8_t *mac, const uint16_t macLen, tls13_cipherSuite_e cs)
{

}

static bool tls13_generate_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *mac, uint16_t macLen, tls13_cipherSuite_e cs)
{

}

static void tls13_encrypt(const uint8_t *plainText, const uint16_t plainTextLen, uint8_t *cipherText, tls13_cipherSuite_e cs)
{

}

static void tls13_decrypt(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *plainText, tls13_cipherSuite_e cs)
{

}

static tls13_cipherSuite_e tls13_getCipherSuite(void)
{
    //return TLS13_AES_128_GCM_SHA256;
    return TLS13_CHACHA20_POLY1305_SHA256;
}

static tls13_signAlgos_e tls13_getSignatureType(void)
{
    return TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256;
}

uint16_t tls13_htons(uint16_t dIn)
{
    uint16_t dOut = 0;
    dOut = ((dIn & 0xFF00) >> 8) | ((dIn & 0x00FF) << 8);
    return dOut;
}

uint32_t tls13_htonss(uint32_t dIn)
{
    uint32_t dOut = 0;
    dOut |= ((dIn & 0x00FF0000) >> 16);
    dOut |= (dIn & 0x0000FF00);
    dOut |= ((dIn & 0x000000FF) << 16);
    return dOut;
}

uint32_t tls13_htonl(uint32_t dIn)
{
    uint32_t dOut = 0;
    dOut |= ((dIn & 0xFF000000) >> 24);
    dOut |= ((dIn & 0x00FF0000) >> 8);
    dOut |= ((dIn & 0x0000FF00) << 8);
    dOut |= ((dIn & 0x000000FF) << 24);
    return dOut;
}

uint64_t tls13_htonll(uint64_t dIn)
{
    uint64_t dOut = 0;
    dOut |= ((dIn & 0xFF00000000000000) >> 56);
    dOut |= ((dIn & 0x00FF000000000000) >> 40);
    dOut |= ((dIn & 0x0000FF0000000000) >> 24);
    dOut |= ((dIn & 0x000000FF00000000) >> 8);
    dOut |= ((dIn & 0x00000000FF000000) << 8);
    dOut |= ((dIn & 0x0000000000FF0000) << 24);
    dOut |= ((dIn & 0x000000000000FF00) << 40);
    dOut |= ((dIn & 0x00000000000000FF) << 56);
    return dOut;
}

uint16_t tls13_ntohs(uint16_t dIn)
{
    uint16_t dOut = 0;
    dOut = ((dIn & 0xFF00) >> 8) | ((dIn & 0x00FF) << 8);
    return dOut;
}

uint32_t tls13_ntohss(uint32_t dIn)
{
    uint32_t dOut = 0;
    dOut |= ((dIn & 0x00FF0000) >> 16);
    dOut |= (dIn & 0x0000FF00);
    dOut |= ((dIn & 0x000000FF) << 16);
    return dOut;
}

uint32_t tls13_ntohl(uint32_t dIn)
{
    uint32_t dOut = 0;
    dOut |= ((dIn & 0xFF000000) >> 24);
    dOut |= ((dIn & 0x00FF0000) >> 8);
    dOut |= ((dIn & 0x0000FF00) << 8);
    dOut |= ((dIn & 0x000000FF) << 24);
    return dOut;
}

uint64_t tls13_ntohll(uint64_t dIn)
{
    uint64_t dOut = 0;
    dOut |= ((dIn & 0xFF00000000000000) >> 56);
    dOut |= ((dIn & 0x00FF000000000000) >> 40);
    dOut |= ((dIn & 0x0000FF0000000000) >> 24);
    dOut |= ((dIn & 0x000000FF00000000) >> 8);
    dOut |= ((dIn & 0x00000000FF000000) << 8);
    dOut |= ((dIn & 0x0000000000FF0000) << 24);
    dOut |= ((dIn & 0x000000000000FF00) << 40);
    dOut |= ((dIn & 0x00000000000000FF) << 56);
    return dOut;
}

/* Global Functions */
uint16_t tls13_prepareClientHello(const uint8_t *clientRandom, const uint8_t *sessionId, const char *dnsHostname, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, uint8_t *tlsPkt)
{
    uint16_t len = 0;
    uint8_t offset = 0;
    uint8_t offsetExt = 0;
    uint16_t recordLen = 0;
    uint32_t handshakeLen = 0;
    tls13_clientHello_t *clientHelloTmp = calloc(1, sizeof(tls13_clientHello_t) + 300);

    /* Record header update */
    clientHelloTmp->recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    clientHelloTmp->recordHeader.protoVersion = tls13_htons(TLS13_PROTO_VERSION);

    /* handshake header update */
    clientHelloTmp->handshakeHeader.handshakeType = TLS13_HST_CLIENT_HELLO;

    clientHelloTmp->clientVersion = tls13_htons(TLS12_PROTO_VERSION);
    /* serialize the 32 Byte random value */
    memcpy(clientHelloTmp->clientRandom, clientRandom, TLS13_RANDOM_LEN);
    clientHelloTmp->sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Serialize the 32 Byte Session Id */
    memcpy(clientHelloTmp->sessionId, sessionId, TLS13_SESSION_ID_LEN);

    /* copy the Ciphersuite data */
    printf("%lx:%lx\n", clientHelloTmp, CLIENTHELLO_CIPHERSUITE_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN));
    CLIENTHELLO_CIPHERSUITE_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN) = tls13_htons(TLS13_CIPHERSUITE_LEN);
    printf("%lx:%lx\n", clientHelloTmp, CLIENTHELLO_CIPHERSUITE_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN));
    printf("%lx:%lx\n", clientHelloTmp, GET_CLIENTHELLO_CIPHERSUITELIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN)); 
    tls13_cipherSuiteData_t *csd = GET_CLIENTHELLO_CIPHERSUITELIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN);
    csd[0] = tls13_htons(TLS13_AES_256_GCM_SHA384);
    csd[1] = tls13_htons(TLS13_CHACHA20_POLY1305_SHA256);
    csd[2] = tls13_htons(TLS13_AES_128_GCM_SHA256);
    csd[3] = tls13_htons(TLS13_EMPTY_RENEGOTIATION_INFO_SCSV);

    /* copy the compression methods (offset by ciphersuite length) */
    CLIENTHELLO_CMPMTHDLIST_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN) = 0x01;
    tls13_compressionMethods_t *cmpMthd = GET_CLIENTHELLO_CMPMTHDLIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN);
    cmpMthd[0] = 0x00;

    /* Initialize the extension length */
    REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, (TLS13_SESSION_ID_LEN + TLS13_SESSION_ID_LEN + TLS13_COMPRESSIONMETHD_LEN), uint16_t) = 0;

    /* Set up the extensions (offset by ciphersuite length) */
    tls13_clientExtensions_t *cExts = GET_CLIENTHELLO_CLIENTEXT_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN, TLS13_COMPRESSIONMETHD_LEN);
    {
        {
            /* Set up the SNI extension data */
            tls13_extensionSNI_t *extSni = &cExts->extSNI;
            extSni->extType = 0x0000; // should be in Big Endian format
            tls13_extSubList_t *sniSub = (tls13_extSubList_t *)&extSni->list;
            {
                //REACH_ELEMENT(sniSub, tls13_extSubList_t, listType, offset, uint8_t) = 0x00; /* DNS Hostname */
                sniSub->listType = 0x00; /* DNS Hostname */
                offset += sizeof(sniSub->listType);
                //REACH_ELEMENT(sniSub, tls13_extSubList_t, listLen, offset, uint16_t) = strlen(dnsHostname);
                sniSub->listLen = tls13_htons(strlen(dnsHostname));
                offset += sizeof(sniSub->listLen);
                memcpy(sniSub->listData, dnsHostname, strlen(dnsHostname)); /* "dns.google.com" */
                offset += strlen(dnsHostname);
            }
            extSni->subListSize = sizeof(tls13_extSubList_t) + offset;
            extSni->extDataLen = extSni->subListSize + sizeof(extSni->subListSize);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (extSni->extDataLen + \
                                                                                                          sizeof(extSni->extDataLen) + \
                                                                                                          sizeof(extSni->extType));
        }
        offsetExt += offset;
        offset = 0;
        {
            /* Set the EC Point Formats extension data */
            tls13_extension2211_t *ecPF = &cExts->extECP + offsetExt;
            ecPF->extType = tls13_htonl(TLS13_EXT_EC_POINTS_FORMAT);
            uint8_t *ecPFList = (uint8_t *)&ecPF->list;
            {
                ecPFList[0] = TLS13_EC_POINT_UNCOMPRESSED;
                ecPFList[1] = TLS13_EC_POINT_ANSIX962_COMPRESSED_PRIME;
                ecPFList[2] = TLS13_EC_POINT_ANSIX962_COMPRESSED_CHAR2;
                offset += 3;
            }
            ecPF->subListSize = offset;
            ecPF->extDataLen = ecPF->subListSize + sizeof(ecPF->subListSize);

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (ecPF->extDataLen + \
                                                                                                          sizeof(ecPF->extDataLen) + \
                                                                                                          sizeof(ecPF->extType));
        }
        offsetExt += offset;
        offset = 0;
        {
            /* Set the supported Group extension data */
            tls13_extension2222_t *supGr = &cExts->extSupprotedGrp + offsetExt;
            supGr->extType = tls13_htonl(TLS13_EXT_SUPPORTED_GROUPS);
            uint16_t *supGrList = (uint16_t *)&supGr->list;
            {
                supGrList[0] = tls13_htonl(TLS13_SUPPGRP_X25519);
                supGrList[1] = tls13_htonl(TLS13_SUPPGRP_SECP256R1);
                supGrList[2] = tls13_htonl(TLS13_SUPPGRP_X448);
                supGrList[3] = tls13_htonl(TLS13_SUPPGRP_SECP521R1);
                supGrList[4] = tls13_htonl(TLS13_SUPPGRP_SECP384R1);
                supGrList[5] = tls13_htonl(TLS13_SUPPGRP_FFDHE2048);
                supGrList[6] = tls13_htonl(TLS13_SUPPGRP_FFDHE3072);
                supGrList[7] = tls13_htonl(TLS13_SUPPGRP_FFDHE4096);
                supGrList[8] = tls13_htonl(TLS13_SUPPGRP_FFDHE6144);
                supGrList[9] = tls13_htonl(TLS13_SUPPGRP_FFDHE8192);
                offset = 10 * 2;
            }
            supGr->subListSize = tls13_htonl(offset); /* each entry of 2 Bytes */
            supGr->extDataLen = supGr->subListSize + sizeof(supGr->subListSize);

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (supGr->extDataLen + \
                                                                                                          sizeof(supGr->extDataLen) + \
                                                                                                          sizeof(supGr->extType));
        }
        offsetExt += offset;
        offset = 0;
        {
            /* set the Session Ticket extension data */
            tls13_extensionNULL_t *sesTic = &cExts->extSessionTicket + offsetExt;
            sesTic->extType = tls13_htonl(TLS13_EXT_SESSION_TICKET);
            sesTic->extDataLen = 0x0000;

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (sesTic->extDataLen + \
                                                                                                          sizeof(sesTic->extDataLen) + \
                                                                                                          sizeof(sesTic->extType));
        }
        {
        /* Set the Encrypt-Then-MAC extension data */
            tls13_extensionNULL_t *enTM = &cExts->extEncryptThenMAC + offsetExt;
            enTM->extType = tls13_htonl(TLS13_EXT_ENCRYPT_THEN_MAC);
            enTM->extDataLen = 0x0000;

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (enTM->extDataLen + \
                                                                                                          sizeof(enTM->extDataLen) + \
                                                                                                          sizeof(enTM->extType));
        }
        {
            /* Set the extended master secret */
            tls13_extensionNULL_t *extMS = &cExts->extExtendedMasterSecret + offsetExt;
            extMS->extType = tls13_htonl(TLS13_EXT_EXT_MASTER_SECRET);
            extMS->extDataLen = 0x0000;

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (extMS->extDataLen + \
                                                                                                          sizeof(extMS->extDataLen) + \
                                                                                                          sizeof(extMS->extType));
        }
        {
            /* Set the Signature Algorithms Extension data */  
            tls13_extension2222_t *sigAlg = &cExts->extSignatureAlgos;
            sigAlg->extType = tls13_htonl(TLS13_EXT_SIGN_AGLORITHM);
            uint16_t *sigAlgList = (uint16_t *)&sigAlg->list;
            {
                sigAlgList[0] = tls13_htonl(TLS13_SIGNALGOS_ECDSA_SECP256r1_SHA256);
                sigAlgList[1] = tls13_htonl(TLS13_SIGNALGOS_ECDSA_SECP384r1_SHA384);
                sigAlgList[2] = tls13_htonl(TLS13_SIGNALGOS_ECDSA_SECP521r1_SHA512);
                sigAlgList[3] = tls13_htonl(TLS13_SIGNALGOS_ED25519);
                sigAlgList[4] = tls13_htonl(TLS13_SIGNALGOS_ED448);
                sigAlgList[5] = tls13_htonl(TLS13_SIGNALGOS_RSA_PSS_PSS_SHA256);
                sigAlgList[6] = tls13_htonl(TLS13_SIGNALGOS_RSA_PSS_PSS_SHA384);
                sigAlgList[7] = tls13_htonl(TLS13_SIGNALGOS_RSA_PSS_PSS_SHA512);
                sigAlgList[8] = tls13_htonl(TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256);
                sigAlgList[9] = tls13_htonl(TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA384);
                sigAlgList[10] = tls13_htonl(TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA512);
                sigAlgList[11] = tls13_htonl(TLS13_SIGNALGOS_RSA_PKCS1_SHA256);
                sigAlgList[12] = tls13_htonl(TLS13_SIGNALGOS_RSA_PKCS1_SHA384);
                sigAlgList[13] = tls13_htonl(TLS13_SIGNALGOS_RSA_PKCS1_SHA512);
                offset = 14 * 2;
            }
            sigAlg->subListSize = tls13_htonl(offset);
            sigAlg->extDataLen = sigAlg->subListSize + sizeof(sigAlg->subListSize);

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (sigAlg->extDataLen + \
                                                                                                          sizeof(sigAlg->extDataLen) + \
                                                                                                          sizeof(sigAlg->extType));
        }
        offsetExt += offset;
        offset = 0;
        {
            /* Set the supported versions extension data */
            tls13_extension2212_t *supVers = &cExts->extSupportedVers + offsetExt;
            supVers->extType = tls13_htonl(TLS13_EXT_SUPPORTED_VERSIONS);
            uint16_t *supVersList = (uint16_t *)&supVers->list;
            {
                supVersList[0] = tls13_htonl(TLS13_PROTO_VERSION);
                offset = 1 * 2;
            }
            supVers->subListSize = tls13_htonl(offset);
            supVers->extDataLen = supVers->subListSize + sizeof(supVers->subListSize);

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (supVers->extDataLen + \
                                                                                                          sizeof(supVers->extDataLen) + \
                                                                                                          sizeof(supVers->extType));
        }
        offsetExt += offset;
        offset = 0;
        {
            /* Set the PSK Key exchange modes extension data */
            tls13_extension2211_t *pskKE = &cExts->extPSKExchangeModes;
            pskKE->extType = tls13_htonl(TLS13_EXT_PSK_KEYXCHANGE_MODES);
            uint8_t *pskKEList = (uint8_t *)&pskKE->list;
            {
                pskKEList[0] = 1; /* 01 - assigned value for "PSK with (EC)DHE key establishment */
                offset = 1 * 1;
            }
            pskKE->subListSize = tls13_htonl(offset);
            pskKE->extDataLen = pskKE->subListSize + sizeof(pskKE->subListSize);

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (pskKE->extDataLen + \
                                                                                                          sizeof(pskKE->extDataLen) + \
                                                                                                          sizeof(pskKE->extType));
        }
        offsetExt += offset;
        offset = 0;        
        {
            /* Set the key share extension data */
            tls13_extensionKeyShare_t *keyS = &cExts->extkeyShare + offsetExt;
            keyS->extType = tls13_htonl(TLS13_EXT_KEY_SHARE);
            keyS->keyShareType = tls13_htonl(TLS13_SUPPGRP_X25519); /* assigned value for x25519 (key exchange via curve25519) */
            {
                memcpy(keyS->pubKey, pubKey, pubKeyLen);
                offset += pubKeyLen;
            }
            keyS->keyShareLen = sizeof(keyS->keyShareType) + sizeof(keyS->pubKeyLen) + keyS->pubKeyLen; /* key share data length */
            keyS->pubKeyLen = tls13_htonl(pubKeyLen);  /* 32  Bytes of public key */
            keyS->extDataLen = keyS->keyShareLen + sizeof(keyS->keyShareLen);

            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t) += (keyS->extDataLen + \
                                                                                                          sizeof(keyS->extDataLen) + \
                                                                                                          sizeof(keyS->extType));
        }
    }

    //CLIENTHELLO_CLIENTEXT_LEN(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN, 1) = 0; // to be updated
    handshakeLen = sizeof(clientHelloTmp->clientVersion) + \
                                                        sizeof(clientHelloTmp->clientRandom) + \
                                                        sizeof(clientHelloTmp->sessionIdLen) + \
                                                        TLS13_SESSION_ID_LEN + \
                                                        sizeof(clientHelloTmp->cipherSuiteLen) + \
                                                        TLS13_CIPHERSUITE_LEN + \
                                                        sizeof(clientHelloTmp->compressionMethodLen) + \
                                                        TLS13_SESSION_ID_LEN + \
                                                        sizeof(clientHelloTmp->extLen) + \
                                                        REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_SESSION_ID_LEN, uint16_t);
    clientHelloTmp->handshakeHeader.handshakeMsgLen = tls13_htonss(handshakeLen);
                                                        
    recordLen = handshakeLen + sizeof(tls13_handshakeHdr_t);

    clientHelloTmp->recordHeader.recordLen = tls13_htons(recordLen);

    /* Finally do a memcopy */
    len = recordLen + TLS13_RECORD_HEADER_SIZE;
    memcpy(tlsPkt, (uint8_t *)clientHelloTmp, len);

    free(clientHelloTmp);
    return len;
}

void tls13_extractClientHello(uint8_t *clientRandom, uint8_t *sessionId, uint8_t *dnsHostname, tls13_capability_t *capability,
                                    uint8_t *pubKey, uint16_t *pubKeyLen, const uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;    
    tls13_clientHello_t *cHello = calloc(1, len);

    assert(cHello->recordHeader.recordType == TLS13_HANDSHAKE_RECORD);
    assert(tls13_ntohl(cHello->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
    assert(cHello->handshakeHeader.handshakeType == TLS13_HST_CLIENT_HELLO);
    assert(tls13_ntohl(cHello->clientVersion) == TLS12_PROTO_VERSION);

    memcpy(clientRandom, cHello->clientRandom, TLS13_RANDOM_LEN);
    memcpy(sessionId, cHello->sessionId, cHello->sessionIdLen);
    offset += cHello->sessionIdLen;

    /* copy the supported cipher suite list to the local buffer */
    if(cHello->cipherSuiteLen > 0){
        memcpy(capability->cipherSuiteList, cHello->cipherSuiteList, cHello->cipherSuiteLen);
        capability->cipherSuiteLen = cHello->cipherSuiteLen;
        offset += cHello->cipherSuiteLen;
    }
    /* Copy the supported compression menthod list to the local buffer */
    if(cHello->compressionMethodLen > 0){
        memcpy(capability->compressionMethodList, cHello->compressionMethodList, cHello->compressionMethodLen);
        capability->compressionMethodLen = cHello->compressionMethodLen;
        offset += cHello->compressionMethodLen;
    }

    tls13_clientExtensions_t *ext = &cHello->clientExt + offset;
    offset = 0;
    {
        /* Server Name Indication (SNI) Extension */
        tls13_extensionSNI_t *sni = &ext->extSNI;
        assert(sni->list->listType == 0x00); /* should be server name - macro needed */
        assert(sni->extType == 0x0000); /* should be hostname - macro  needed */
        memcpy(capability->hostname, sni->list->listData, sni->list->listLen);
        offset += sni->extDataLen;
                  
        /* EC Point Formats extension */
        tls13_extension2211_t *ecp = &ext->extECP + offset;
        assert(ecp->extType == TLS13_EXT_EC_POINTS_FORMAT);
        memcpy(capability->ecPoints, ecp->list, ecp->subListSize);
        capability->ecFormatsLen = ecp->subListSize;
        offset += ecp->extDataLen;

        /* Supported Groups Extension */               
        tls13_extension2222_t *sgr = &ext->extSupprotedGrp + offset;
        assert(sgr->extType == TLS13_EXT_SUPPORTED_GROUPS);
        memcpy(capability->supportedGrp, sgr->list, sgr->subListSize);
        capability->supportedGrpLen = sgr->subListSize;
        offset += sgr->subListSize;

        /* extension data length is 0 - session ticket */         
        tls13_extensionNULL_t *stkt = &ext->extSessionTicket + offset;
        assert(stkt->extType == TLS13_EXT_SESSION_TICKET);
        if(stkt->extDataLen > 0x0000){
            /* To be handled */
        }

        /* extension data length is 0 - Encrypt-Then-MAC */         
        tls13_extensionNULL_t *etm = &ext->extEncryptThenMAC + offset;
        assert(etm->extType == TLS13_EXT_ENCRYPT_THEN_MAC);
        if(etm->extDataLen > 0x0000){
            /* To be handled */
        }

        /* extension data length is 0 - extended master secret */       
        tls13_extensionNULL_t *ems = &ext->extExtendedMasterSecret + offset;
        assert(ems->extType == TLS13_EXT_EXT_MASTER_SECRET);
        if(ems->extDataLen > 0x0000){
            /* to be handled */
        }

        /* Signature Algorithms Extension */
        tls13_extension2222_t *esa = &ext->extSignatureAlgos + offset;
        assert(esa->extType = TLS13_EXT_SIGN_AGLORITHM);
        memcpy(capability->signAlgos, esa->list, esa->subListSize);
        capability->signAlgoLen = esa->subListSize;
        offset += esa->subListSize;

        /* supported versions */       
        tls13_extension2212_t *esv = &ext->extSupportedVers + offset;
        assert(esv->extType = TLS13_EXT_SUPPORTED_VERSIONS);
        memcpy(capability->supportedVersions, esv->list, esv->subListSize);
        capability->supportedVersionLen = esv->subListSize;
        offset += esv->subListSize;

        /* PSK key exchange modes */
        tls13_extension2211_t *epskkem = &ext->extPSKExchangeModes + offset;
        assert(epskkem->extType == TLS13_EXT_PSK_KEYXCHANGE_MODES);
        assert(epskkem->list[0] == 1); /* 01 - assigned value for "PSK with (EC)DHE key establishment */
        assert(epskkem->subListSize == 1);
        memcpy(capability->keyXchangeModes, epskkem->list, epskkem->subListSize);
        capability->keyXchangeModesLen = epskkem->subListSize;
        offset += epskkem->subListSize;

        /* Key share */
        tls13_extensionKeyShare_t *ks = &ext->extkeyShare + offset;
        assert(ks->extType == TLS13_EXT_KEY_SHARE);
        assert(ks->keyShareType == 0x001D); /* assigned value for x25519 (key exchange via curve25519) */
        assert(ks->keyShareLen == 2);
        memcpy(pubKey, ks->pubKey, ks->pubKeyLen);
        *pubKeyLen = ks->pubKeyLen;
    }
}

uint16_t tls13_prepareServerHello(const uint8_t *serverRandom, const uint8_t *sessionId, const uint16_t cipherSuite, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, const uint16_t keyType, const uint8_t *encryExt, const uint16_t encryExtLen, 
                                    uint8_t *tlsPkt)
{
    uint16_t len = 0;
    tls13_cipherSuite_e cs = tls13_getCipherSuite();
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
            eKS->keyShareType = keyType;//0x001D; /* assigned value for x25519 (key exchange via curve25519) */
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
    {
        sCCS->recordHeader.recordType   = TLS13_CHANGE_CIPHERSPEC_RECORD;
        sCCS->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        sCCS->payload                   = 0x01;
        sCCS->recordHeader.recordLen    = 0x0001;
    }

    /* Fill and serialize the first wrapped record with encrypted data */
    tls13_wrappedRecord_t *rec = &serverHelloTmp->record1 + serverHelloTmp->serverHello.recordHeader.recordLen + sizeof(tls13_changeCipherSpec_t);
    {
        rec->recordHeader.recordType = TLS13_APPDATA_RECORD;
        rec->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* legacy TLS 1.2 */
        tls13_encryExt_t *dataTmp = calloc(1, 100);
        dataTmp->handshakeHdr.handshakeType = TLS13_HST_ENCRYPTED_EXT;
        dataTmp->handshakeHdr.handshakeMsgLen = encryExtLen + 0x02;
        dataTmp->extLen = encryExtLen;
  
        tls13_encrypt((uint8_t *)dataTmp, sizeof(tls13_encryExt_t) + dataTmp->extLen, (uint8_t *)rec->encryptedData, cs);
        //memcpy(rec->encryptedData, dataTmp, dataLen);     /* encrypted data with server handshake key */
        //memcpy(rec->authTag + dataLen, authTag, TLS13_RECORD_AUTHTAG_LEN);      /* 16 Byte auth tag */
        tls13_generate_authTag(encryExt, encryExtLen, (rec->authTag + encryExtLen), TLS13_RECORD_AUTHTAG_LEN, cs);
        rec->recordHeader.recordLen = sizeof(tls13_encryExt_t) + encryExtLen + TLS13_RECORD_AUTHTAG_LEN;
        free(dataTmp);
    }
    len = serverHelloTmp->serverHello.recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE + \
                                                                sCCS->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE + \
                                                                rec->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
    /* Finally do a memory copy */
    memcpy(tlsPkt, (uint8_t *)serverHelloTmp, len);
    free(serverHelloTmp);

    return len;
}

void tls13_extractServerHello(uint8_t *serverRandom, uint8_t *sessionId, uint16_t *cipherSuite, 
                                    uint8_t *pubKey, uint16_t *pubKeyLen, uint16_t *keyType, uint8_t *encryExt, uint16_t *encryExtLen, const uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    tls13_cipherSuite_e cs = tls13_getCipherSuite();
    uint16_t helloLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t changeCSLen = ((uint16_t)tlsPkt[helloLen + 3] << 8 | tlsPkt[helloLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t appDataLen = ((uint16_t)tlsPkt[helloLen + changeCSLen + 3] << 8 | tlsPkt[helloLen + changeCSLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tls13_serverHellowCompat_t *tmp = calloc(1, helloLen + changeCSLen + appDataLen);
    {
        tls13_serverHello_t *sHello = &tmp->serverHello;
        assert(sHello->recordHeader.recordType == TLS13_HST_SERVER_HELLO);
        assert(sHello->recordHeader.protoVersion == TLS12_PROTO_VERSION || sHello->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        assert(sHello->serverVersion == TLS13_PROTO_VERSION);
        memcpy(serverRandom, sHello->serverRandom, TLS13_RANDOM_LEN);
        memcpy(sessionId, sHello->sessionId, sHello->sessionIdLen);
        offset += sHello->sessionIdLen;
        *cipherSuite = REACH_ELEMENT(sHello, tls13_serverHello_t, cipherSuiteSelect, offset, uint16_t);
        //REACH_ELEMENT(sHello, tls13_serverHello_t, compressionMethodSelect, offset, uint16_t);
        tls13_serverExtensions_t *serExt = &sHello->serverExt + offset;
        {
            assert(serExt->extSupportedVers.extType == TLS13_EXT_SUPPORTED_VERSIONS);
            assert(serExt->extSupportedVers.extData == TLS13_PROTO_VERSION);
            assert(serExt->extSupportedVers.extDataLen == 2);
            assert(serExt->extkeyShare.extType == TLS13_EXT_KEY_SHARE);
            *keyType = serExt->extkeyShare.keyShareType;
            *pubKeyLen = serExt->extkeyShare.pubKeyLen;
            memcpy(pubKey, serExt->extkeyShare.pubKey, *pubKeyLen);
        }
    }
    /* Server change cipher spec */
    {
        tls13_changeCipherSpec_t *ccs = &tmp->serverCCS + offset;
        assert(ccs->recordHeader.recordType == TLS13_CHANGE_CIPHERSPEC_RECORD);
        assert(ccs->recordHeader.protoVersion == TLS12_PROTO_VERSION || ccs->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        assert(ccs->payload == 0x01);
        assert(ccs->recordHeader.recordLen == 0x0001);
    }
    /* Server encrypted extension */
    {
        tls13_wrappedRecord_t *data = &tmp->record1 + offset;
        assert(data->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(data->recordHeader.protoVersion == TLS12_PROTO_VERSION || data->recordHeader.protoVersion == TLS13_PROTO_VERSION);

        tls13_encryExt_t *dataTmp = calloc(1, data->recordHeader.recordLen);
        uint16_t dataLen = data->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
        tls13_decrypt((uint8_t *)data->encryptedData, dataLen, (uint8_t *)dataTmp, cs);
        assert(dataTmp->handshakeHdr.handshakeType == TLS13_HST_ENCRYPTED_EXT);

        uint16_t encryExtLenTmp = dataTmp->extLen;
        if(encryExtLenTmp)
        {
            memcpy(encryExt, dataTmp->extList, encryExtLenTmp);
        }
        *encryExtLen = encryExtLenTmp;
        free(dataTmp);
        /* Generate Mac of the received encrypted data */
        assert(true == tls13_verify_authTag(data->encryptedData, dataLen, data->authTag + dataLen, TLS13_RECORD_AUTHTAG_LEN, cs));
    }
    free(tmp);
}

uint16_t tls13_prepareServerWrappedRecord(const uint8_t *dCert, const uint16_t dCertLen, 
                                        const uint8_t *dCertVerf, const uint16_t dCertVerfLen, 
                                        const uint8_t *dVerify, const uint16_t dVerifyLen, uint8_t *tlsPkt)
{
    uint32_t len = 0;
    uint16_t offset = 0;
    tls13_cipherSuite_e cs = tls13_getCipherSuite();
    tls13_serverWrappedRecord_t *record = calloc(1, (sizeof(tls13_serverWrappedRecord_t) + 1200));

    // should be able to send certificate request, if certificate is expected from the client
    /* certificate */
    tls13_certRecord_t *certRecord = &record->certRecord;
    {
        uint16_t certRecordLen = 0;
        certRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        certRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */

        tls13_certRecordDataDecrypt_t *certR = calloc(1, dCertLen + TLS13_HANDSHAKE_HEADER_SIZE + 3 + 2);
        certR->certificate.handshakeHdr.handshakeType = TLS13_HST_CERTIFICATE;
        certR->certificate.requestContext = 0x00;
        certR->certificate.cert->certLen = dCertLen;
        memcpy(certR->certificate.cert->cert, dCert, dCertLen);
        certR->certificate.cert->certExtension = 0x0000;
        certR->certificate.payloadLen = dCertLen + 3 + 2;
        //certR->recordType = /* No footer for handshake (record type)
        certR->certificate.handshakeHdr.handshakeMsgLen = certR->certificate.payloadLen;
        certRecordLen = certR->certificate.handshakeHdr.handshakeMsgLen + TLS13_HANDSHAKE_HEADER_SIZE;
        /* Encrypt the data before copying */
        tls13_encrypt((uint8_t *)certRecord->encryptedData, certRecordLen, (uint8_t *)certR, cs);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += dCertLen;
        //memcpy(certRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(certRecord->encryptedData, dCertLen, (certRecord->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
        offset += TLS13_RECORD_AUTHTAG_LEN;  
        certRecord->recordHeader.recordLen = offset + sizeof(tls13_certRecordDataDecrypt_t);
        /* Number of bytes so far */
        len += certRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
        free(certR);
    }
    offset = 0;
    /* certificate verification */
    tls13_certVerifyRecord_t *certVerifyRecord = &record->certVerifyRecord + len; 
    {
        certVerifyRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        certVerifyRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */

        tls13_certVerifyRecordDataDecrypt_t *certVerif = calloc(1, dCertVerfLen + TLS13_HANDSHAKE_HEADER_SIZE + 1);
        certVerif->certVerify.handshakeHdr.handshakeType = TLS13_HST_CERTIFICATE_VERIFY;
        certVerif->certVerify.handshakeHdr.handshakeMsgLen = dCertVerfLen + sizeof(tls13_signature_t);
        certVerif->recordType = TLS13_HANDSHAKE_RECORD;
        /* Encrypt the data before copying */
        certVerif->certVerify.sign.signType = (uint16_t)tls13_getSignatureType();
        certVerif->certVerify.sign.signLen = dCertVerfLen;
        memcpy(certVerif->certVerify.sign.sign, dCertVerf, dCertVerfLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset += dCertVerfLen; // tls13_signature_t -> need to check the impact of size
        tls13_encrypt((uint8_t *)certVerif, dCertVerfLen + 4 + TLS13_HANDSHAKE_HEADER_SIZE, (uint8_t *)certVerifyRecord->encryptedData, cs);
        //memcpy(certVerifyRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(certVerifyRecord->encryptedData, dCertVerfLen, (certVerifyRecord->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
        offset += TLS13_RECORD_AUTHTAG_LEN;

        certVerifyRecord->recordHeader.recordLen = offset + sizeof(tls13_certVerifyRecordDataDecrypt_t);
        /* Number of Bytes so far */
        len += certVerifyRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
        free(certVerif);
    }
    offset = 0;
    tls13_finishedRecord_t *finishedRecord = &record->finishedRecord + len;
    {
        finishedRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        
        tsl13_finishedRecordDataDecrypted_t *verf = calloc(1, dVerifyLen + TLS13_HANDSHAKE_HEADER_SIZE);
        verf->finished.handshakeHdr.handshakeType = TLS13_HST_FINISHED;
        verf->finished.handshakeHdr.handshakeMsgLen = dVerifyLen;
        //verf->recordType = TLS13_HANDSHAKE_RECORD;
        /* Encrypt the data before copying */
        memcpy(verf->finished.verifyData, dVerify, dVerifyLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        tls13_encrypt((uint8_t *)verf, dVerifyLen + TLS13_HANDSHAKE_HEADER_SIZE, (uint8_t *)finishedRecord->encryptedData, cs);
        offset += dVerifyLen;
        //memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(finishedRecord->encryptedData, dVerifyLen, (finishedRecord->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
     
        finishedRecord->recordHeader.recordLen = offset + sizeof(tsl13_finishedRecordDataDecrypted_t);
        /* NUmber of Bytes so far */
        len += finishedRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
        free(verf);
    }

    memcpy(tlsPkt, (uint8_t *)record, len);
    free(record);
    return len;
}

void tls13_extractServerWrappedRecord(const uint8_t *tlsPkt, tls13_cert_t *dCert, tls13_signature_t *sign, uint8_t *dVerify, uint16_t *dVerifyLen)
{
    uint16_t authTagOffset = 0;
    tls13_cipherSuite_e cs = tls13_getCipherSuite();    
    uint16_t certLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t certVerfLen = ((uint16_t)tlsPkt[certLen + 3] << 8 | tlsPkt[certLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t verfLen = ((uint16_t)tlsPkt[certLen + certVerfLen + 3] << 8 | tlsPkt[certLen + certVerfLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tls13_serverWrappedRecord_t *tmp = calloc(1, certLen + certVerfLen + verfLen);

    if(tlsPkt[6] == TLS13_HST_CERTIFICATE){
        tls13_certRecord_t *recvdCertRecord = &tmp->certRecord;
        authTagOffset = recvdCertRecord->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
        /* Some basic assertion to check for pkt deformity */
        assert(recvdCertRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdCertRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdCertRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        assert(true == tls13_verify_authTag(recvdCertRecord->encryptedData, authTagOffset, 
                                            (recvdCertRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));

        //tls13_certRecordDataDecrypt_t *dCertTemp = (tls13_certRecordDataDecrypt_t *)&recvdCertRecord->encryptedData;
        tls13_certRecordDataDecrypt_t *dCertTemp = calloc(1, certLen);
        tls13_decrypt((uint8_t *)recvdCertRecord->encryptedData, certLen, (uint8_t *)dCertTemp, cs);
        //assert(dCertTemp->recordType == TLS13_HANDSHAKE_RECORD);
        assert(dCertTemp->certificate.handshakeHdr.handshakeType == TLS13_HST_CERTIFICATE);

        dCert->certLen = dCertTemp->certificate.cert->certLen;
        if(dCert->cert != NULL){
            /* Certificate will be in ASN.1 DER encoding and unencrypted */
            memcpy(dCert->cert, dCertTemp->certificate.cert->cert, dCert->certLen);
        }
        dCert->certExtension = REACH_ELEMENT(dCertTemp->certificate.cert, tls13_cert_t, certExtension, dCert->certLen, uint16_t);
        free(dCertTemp);
    }
    if(tlsPkt[6 + certLen] == TLS13_HST_CERTIFICATE_VERIFY)
    {
        tls13_certVerifyRecord_t *recvdCertVerifyRecord = (tls13_certVerifyRecord_t *)&tmp->certVerifyRecord + certLen;
        authTagOffset = recvdCertVerifyRecord->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
        assert(recvdCertVerifyRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdCertVerifyRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdCertVerifyRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        assert(true == tls13_verify_authTag(recvdCertVerifyRecord->encryptedData, authTagOffset, 
                                            (recvdCertVerifyRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));
        
        //tls13_certVerifyRecordDataDecrypt_t *dSign = (tls13_certVerifyRecordDataDecrypt_t *)&recvdCertVerifyRecord->encryptedData;
        tls13_certVerifyRecordDataDecrypt_t *dSign = calloc(1, certVerfLen);
        tls13_decrypt((uint8_t *)recvdCertVerifyRecord->encryptedData, certVerfLen, (uint8_t *)sign, cs); 
        assert(dSign->recordType == TLS13_HANDSHAKE_RECORD);
        assert(dSign->certVerify.handshakeHdr.handshakeType == TLS13_HST_CERTIFICATE_VERIFY);
        sign->signType = dSign->certVerify.sign.signType;
        sign->signLen = dSign->certVerify.sign.signLen;
        if(sign->sign != NULL){
            /* Signature would be on handshake hash and will be encrypted */
            memcpy(sign->sign, dSign->certVerify.sign.sign, sign->signLen);
        }
        free(dSign);
    }
    if(tlsPkt[6 + certLen + certVerfLen] == TLS13_HST_FINISHED)
    {
        tls13_finishedRecord_t *recvdFinRecord = &tmp->finishedRecord + certLen + certVerfLen;
        authTagOffset = recvdFinRecord->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
        assert(recvdFinRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdFinRecord->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdFinRecord->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        assert(true == tls13_verify_authTag(recvdFinRecord->encryptedData, authTagOffset, 
                                            (recvdFinRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));

        //tsl13_finishedRecordDataDecrypted_t *verf = (tsl13_finishedRecordDataDecrypted_t *)&recvdFinRecord->encryptedData;
        tsl13_finishedRecordDataDecrypted_t *verf = calloc(1, verfLen);
        tls13_decrypt((uint8_t *)recvdFinRecord->encryptedData, verfLen - TLS13_RECORD_HEADER_SIZE, (uint8_t *)verf, cs);
        //assert(verf->recordType == TLS13_HANDSHAKE_RECORD);
        assert(verf->finished.handshakeHdr.handshakeType == TLS13_HST_FINISHED);

        if(dVerify != NULL){
            //memcpy(dVerify, verf->finished.verifyData, verfLen - TLS13_RECORD_HEADER_SIZE);
            memcpy(dVerify, verf->finished.verifyData, verfLen - TLS13_RECORD_HEADER_SIZE);
            *dVerifyLen = verfLen - TLS13_RECORD_HEADER_SIZE;
        }
        free(verf);
    }      
    free(tmp);
}

uint16_t tls13_prepareClientWrappedRecord(const uint8_t *dVerify, const uint16_t dVerifyLen, 
                                            const uint8_t *appData, const uint8_t appDataLen, uint8_t *tlsPkt)
{
    uint32_t len = 0;
    uint16_t offset = 0;
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 
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
    // If client also wands to respond to a certificate request, it should be able to send certificate and cert verify records
    tls13_finishedRecord_t *finishedRecord = &record->finishedRecord + len;
    {
        finishedRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        
        tsl13_finishedRecordDataDecrypted_t *verif = calloc(1, 200);
        verif->finished.handshakeHdr.handshakeType = TLS13_HST_FINISHED;
        verif->finished.handshakeHdr.handshakeMsgLen = dVerifyLen;
        /* Data to be encrypted before copying */
        memcpy(verif->finished.verifyData, dVerify, dVerifyLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        tls13_encrypt((uint8_t *)verif, dVerifyLen + TLS13_HANDSHAKE_HEADER_SIZE, (uint8_t *)finishedRecord->encryptedData, cs);
        offset += dVerifyLen;
        //memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(finishedRecord->encryptedData, dVerifyLen, finishedRecord->authTag + offset, TLS13_RECORD_AUTHTAG_LEN, cs);
        offset += TLS13_RECORD_AUTHTAG_LEN;
     
        finishedRecord->recordHeader.recordLen = offset;
        len += finishedRecord->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;
        free(verif);
    }
    offset = 0;
    tls13_appDataRecord_t *aDR = &record->appDataRecord + len;
    if(appData != NULL && appDataLen > 0)
    {
        aDR->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        aDR->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        /* Data to be encrypted before copying */
        //memcpy(aDR->encryptedData, appData, appDataLen);    // encrypted data length to be standardised. data encrypted with the server handshake key
        tls13_encrypt(appData, appDataLen, (uint8_t *)aDR->encryptedData, cs);
        offset += appDataLen;
        //memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(aDR->encryptedData, appDataLen, aDR->authTag + offset, TLS13_RECORD_AUTHTAG_LEN, cs);
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
    uint16_t authTagOffset = 0;
    uint16_t ccspLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t verifLen = ((uint16_t)tlsPkt[ccspLen + 3] << 8 | tlsPkt[ccspLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t dataLen = ((uint16_t)tlsPkt[ccspLen + verifLen + 3] << 8 | tlsPkt[ccspLen + verifLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tls13_clientWrappedRecord_t *tmp = calloc(1, ccspLen + ccspLen + verifLen);
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 

    if(tlsPkt[0] == TLS13_CHANGE_CIPHERSPEC_RECORD)
    {
        tls13_changeCipherSpec_t *recvdChangeCipherSpec = &tmp->clientCCS;
        assert(recvdChangeCipherSpec->recordHeader.recordType == TLS13_CHANGE_CIPHERSPEC_RECORD);
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
        authTagOffset = recvdFinRecord->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
        assert(true == tls13_verify_authTag(recvdFinRecord->encryptedData, authTagOffset, 
                                            (recvdFinRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));  
        
        //tsl13_finishedRecordDataDecrypted_t *verf = (tsl13_finishedRecordDataDecrypted_t *)&recvdFinRecord->encryptedData;
        tsl13_finishedClientRecordDataDecrypted_t *verf = calloc(1, verifLen);
        tls13_decrypt((uint8_t *)recvdFinRecord->encryptedData, verifLen - TLS13_RECORD_HEADER_SIZE, (uint8_t *)verf, cs);
        assert(verf->recordType == TLS13_HANDSHAKE_RECORD);
        assert(verf->finished.handshakeHdr.handshakeType == TLS13_HST_FINISHED);

        if(dVerify != NULL){
            memcpy(dVerify, verf->finished.verifyData, verifLen - TLS13_RECORD_HEADER_SIZE); // decrypt before copying
            *dVerifyLen = verifLen - TLS13_RECORD_HEADER_SIZE;
        }
        free(verf);
    }
    if(tlsPkt[ccspLen + verifLen] == TLS13_APPDATA_RECORD)
    {
        tls13_appDataRecord_t *recvdAppData = (tls13_appDataRecord_t *)(&tmp->appDataRecord + ccspLen + verifLen);       
        assert(recvdAppData->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(recvdAppData->recordHeader.protoVersion == TLS12_PROTO_VERSION || recvdAppData->recordHeader.protoVersion == TLS13_PROTO_VERSION);
        /* Verify the auth Tag */
        authTagOffset = recvdAppData->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
        assert(true == tls13_verify_authTag(recvdAppData->encryptedData, authTagOffset, 
                                            (recvdAppData->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs)); 
        if(dVerify != NULL){
            //memcpy(appData, recvdAppData->encryptedData, verifLen - TLS13_RECORD_HEADER_SIZE); // need to decrypt data before copying
            tls13_decrypt(recvdAppData->encryptedData, verifLen - TLS13_RECORD_HEADER_SIZE, appData, cs);
            *appDataLen = dataLen - TLS13_RECORD_HEADER_SIZE;
        }
    }      
    free(tmp);
}

uint16_t tls13_prepareServerSessionTicketRecord(const uint8_t *sessionTkt, const uint8_t sessionTktLen, uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_serverSesTktWrappedRecord_t *sNST = calloc(1, (sizeof(tls13_serverSesTktWrappedRecord_t) + 1200));
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 

    sNST->recordHeader.recordType = TLS13_APPDATA_RECORD;
    sNST->recordHeader.protoVersion = TLS12_PROTO_VERSION;      /* Legacy TLS 1.2 */
    //memcpy(&sNST->encryptedData, sessionTkt, sessionTktLen);    // session ticket with the server handshake key
    tls13_encrypt(sessionTkt, sessionTktLen, (uint8_t *)sNST->encryptedData, cs);
    offset += sessionTktLen;
    //memcpy(sNST->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
    tls13_generate_authTag(sNST->encryptedData, sessionTktLen, sNST->authTag + offset, TLS13_RECORD_AUTHTAG_LEN, cs);
    offset += TLS13_RECORD_AUTHTAG_LEN;

    sNST->recordHeader.recordLen = offset;
        
    len = sNST->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE; 
    memcpy(tlsPkt, (uint8_t *)sNST, len);
    free(sNST);
    return len;
}

void tls13_extractSessionTicket(tls13_serverNewSesTkt_t *sessionTkt, const uint8_t *tlsPkt)
{
    uint16_t dataSize = 0;
    uint16_t offset = 0;

    uint16_t pktLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    tls13_serverSesTktWrappedRecord_t *tmp = calloc(1, pktLen);
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 
    memcpy((uint8_t *)tmp, tlsPkt, pktLen);

    /* Some basic assertion to check for pkt deformity */
    assert(tmp->recordHeader.recordType == TLS13_APPDATA_RECORD);
    assert(tmp->recordHeader.protoVersion == TLS12_PROTO_VERSION || tmp->recordHeader.protoVersion == TLS13_PROTO_VERSION);
    //assert((tmp->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE) == pktSize);

    dataSize = tmp->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
    //memcpy(authTag, (tmp->authTag + dataSize), TLS13_RECORD_AUTHTAG_LEN);
    assert(true == tls13_verify_authTag(tmp->encryptedData, dataSize, (tmp->authTag + dataSize), TLS13_RECORD_AUTHTAG_LEN, cs));


    //tsl13_serverSesTktDataDecrypt_t *tmp1 = (tsl13_serverSesTktDataDecrypt_t *)&tmp->encryptedData;
    tsl13_serverSesTktDataDecrypt_t *tmp1 = calloc(1, dataSize);
    /* decrypt the data */
    tls13_decrypt(tmp->encryptedData, dataSize, (uint8_t *)tmp1, cs);
    assert(tmp1->recordType == TLS13_HANDSHAKE_RECORD);
    sessionTkt->handshakeHdr.handshakeType = tmp1->sessionTicket.handshakeHdr.handshakeType;
    sessionTkt->handshakeHdr.handshakeMsgLen = tmp1->sessionTicket.handshakeHdr.handshakeMsgLen;
    sessionTkt->ticketLifetime = 
    sessionTkt->ticketAgeAdd =

    sessionTkt->nounceLen = tmp1->sessionTicket.nounceLen;
    if(sessionTkt->nounce != NULL)
        memcpy(sessionTkt->nounce, tmp1->sessionTicket.nounce, sessionTkt->nounceLen);
    offset += sessionTkt->nounceLen;

    //sessionTkt->sessionTicketLen = tmp1->sessionTicket.sessionTicketLen;
    sessionTkt->sessionTicketLen = REACH_ELEMENT(&tmp1->sessionTicket, tls13_serverNewSesTkt_t, sessionTicketLen, offset, uint8_t);
    if(sessionTkt->sessionTicket != NULL)
        memcpy(sessionTkt->sessionTicket, tmp1->sessionTicket.nounce + offset, sessionTkt->sessionTicketLen);
    offset += sessionTkt->sessionTicketLen;

    //sessionTkt->ticketExtensionLen = tmp1->sessionTicket.ticketExtensionLen;
    sessionTkt->ticketExtensionLen = REACH_ELEMENT(&tmp1->sessionTicket, tls13_serverNewSesTkt_t, ticketExtensionLen, offset, uint16_t);
    if(sessionTkt->extList != NULL) 
        memcpy(sessionTkt->extList, &tmp1->sessionTicket.extList + offset, sessionTkt->ticketExtensionLen);
    free(tmp);
    free(tmp1);
}

/* There should be a max cap to the dataLen. Data length should be inclusive of padding  */
/* TLS pkt is expected to be in little endian format */
uint16_t tls13_prepareAppData(const uint8_t *dIn, const uint16_t dInLen, uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_appDataRecord_t *app = calloc(1, sizeof(tls13_appDataRecord_t));
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 

    app->recordHeader.recordType   = TLS13_APPDATA_RECORD;
    app->recordHeader.protoVersion = TLS12_PROTO_VERSION;      /* Legacy TLS 1.2 */

    /* Need to encrypt data */
    //memcpy(app->encryptedData, dIn, dInLen);    /* data encrypted with the server handshake key */
    tls13_encrypt(dIn, dInLen, app->encryptedData, cs);
    offset += dInLen;

    //memcpy(app->authTag, authTag, TLS13_RECORD_AUTHTAG_LEN);
    tls13_generate_authTag(dIn, dInLen, (app->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
    offset += TLS13_RECORD_AUTHTAG_LEN;

    app->recordHeader.recordLen = offset;      
    len = app->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;  
    memcpy(tlsPkt, (uint8_t *)app, len);
    free(app);

    return len;
}

void tls13_extractEncryptedAppData(uint8_t *dOut, uint16_t *dOutLen, const uint8_t *tlsPkt)
{
    uint16_t dataSize = 0;
    uint16_t pktLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    tls13_appDataRecord_t *tmp = calloc(1, pktLen);
    memcpy((uint8_t *)tmp, tlsPkt, pktLen);
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 

    /* Some basic assertion to check for pkt deformity */
    assert(tmp->recordHeader.recordType == TLS13_APPDATA_RECORD);
    assert(tmp->recordHeader.protoVersion == TLS12_PROTO_VERSION || tmp->recordHeader.protoVersion == TLS13_PROTO_VERSION);
    //assert((tmp->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE) == pktLen);

    dataSize = tmp->recordHeader.recordLen - TLS13_RECORD_AUTHTAG_LEN;
    /* Need to decrypt the data before copying to buffer */
    //memcpy(dOut, tmp->encryptedData, dataSize);
    tls13_decrypt(tmp->encryptedData, dataSize, dOut, cs);
    *dOutLen = dataSize;

    // memcpy(authTag, tmp->authTag, TLS13_RECORD_AUTHTAG_LEN);
    assert(true == tls13_verify_authTag(tmp->encryptedData, dataSize, (tmp->authTag + dataSize), TLS13_RECORD_AUTHTAG_LEN, cs));
    free(tmp);
}

uint16_t tls13_prepareAlertRecord(const tls13_alert_t *alertData, uint8_t *tlsPkt)
{
    uint16_t len = 0;
    uint16_t offset = 0;
    tls13_wrappedAlertRecord_t *war = calloc(1, 100);
    tls13_alert_t alert;
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 

    war->recordHeader.recordType = TLS13_ALERT_RECORD;
    war->recordHeader.protoVersion = TLS12_PROTO_VERSION; // wrapping for compatibility with TLS 1.2
    {
        alert.level = alertData->level;
        alert.description = alertData->description;
    }
    tls13_encrypt((uint8_t *)&alert, sizeof(tls13_alert_t), (uint8_t *)&war->alert, cs);
    offset += sizeof(tls13_alert_t);
    tls13_generate_authTag((uint8_t *)&war->alert, sizeof(tls13_alert_t), (war->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
    //memcpy(war->authTag, authTag, TLS13_RECORD_AUTHTAG_LEN);
    war->recordHeader.recordLen = offset + TLS13_RECORD_AUTHTAG_LEN;
    len += war->recordHeader.recordLen + TLS13_RECORD_HEADER_SIZE;

    memcpy(tlsPkt, (uint8_t *)war, len);
    free(war);
    return len;
}

void tls13_extractAlertRecord(tls13_alert_t *alertData, const uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    tls13_wrappedAlertRecord_t *war = calloc(1, 100);
    tls13_cipherSuite_e cs = tls13_getCipherSuite(); 

    assert(war->recordHeader.recordType == TLS13_ALERT_RECORD);
    assert(war->recordHeader.protoVersion == TLS13_PROTO_VERSION || war->recordHeader.protoVersion == TLS12_PROTO_VERSION);
    assert(war->recordHeader.recordLen == (sizeof(tls13_alert_t) + TLS13_RECORD_AUTHTAG_LEN));
    //memcpy(alertData, &war->alert, sizeof(tls13_alert_t));
    tls13_decrypt((uint8_t *)&war->alert, sizeof(tls13_alert_t), (uint8_t *)alertData, cs);
    offset += sizeof(tls13_alert_t);
    tls13_verify_authTag((uint8_t *)&war->alert, sizeof(tls13_alert_t), (war->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
    free(war);
}