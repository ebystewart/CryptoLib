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


/* Static function definitions */

static bool tls13_verify_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, const uint8_t *mac, const uint16_t macLen, tls13_cipherSuite_e cs)
{
    return true;
}

static bool tls13_generate_authTag(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *mac, uint16_t macLen, tls13_cipherSuite_e cs)
{
    memset(mac, 0xFB, macLen);
}

static void tls13_encrypt(const uint8_t *plainText, const uint16_t plainTextLen, uint8_t *cipherText, tls13_cipherSuite_e cs)
{
    memcpy(cipherText, plainText, plainTextLen);
}

static void tls13_decrypt(const uint8_t *cipherText, const uint16_t cipherTextLen, uint8_t *plainText, tls13_cipherSuite_e cs)
{
    memcpy(plainText, cipherText, cipherTextLen);
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
    uint16_t tempLen;
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
    printf("%lx:%lx\n", clientHelloTmp, GET_CLIENTHELLO_CMPMTHDLIST_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN)); 
    cmpMthd[0] = 0x00;//0xBB;

    /* Initialize the extension length */
    printf("%lx:%lx\n", clientHelloTmp, &REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t)); 
    REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) = 0x0000; //0xCCCC/* initialize a pattern to identify */

    /* Set up the extensions (offset by ciphersuite length) */
    tls13_clientExtensions_t *cExts = GET_CLIENTHELLO_CLIENTEXT_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN, TLS13_COMPRESSIONMETHD_LEN);
    printf("%lx:%lx\n", clientHelloTmp, GET_CLIENTHELLO_CLIENTEXT_PTR(clientHelloTmp, TLS13_SESSION_ID_LEN, TLS13_CIPHERSUITE_LEN, TLS13_COMPRESSIONMETHD_LEN)); 

    //tls13_clientExtensions_t *cExts = (tls13_clientExtensions_t *)((uint8_t *)&clientHelloTmp->clientExt + TLS13_CLIENT_EXT_OFFSET);
    {
        {
            /* Set up the SNI extension data */
            tls13_extensionSNI_t *extSni = &cExts->extSNI;
            extSni->extType = tls13_htons(0x0000); // 0x0000 - should be in Big Endian format
            extSni->subListSize = 0xDCCD; // for test
            extSni->extDataLen = 0xAFAF; // for test
            tls13_extSubList_t *sniSub = (tls13_extSubList_t *)&extSni->list[0];
            {
                //REACH_ELEMENT(sniSub, tls13_extSubList_t, listType, offset, uint8_t) = 0x00; /* DNS Hostname */
                sniSub->listType = 0x00; /* DNS Hostname */
                offset += strlen(dnsHostname);
                //REACH_ELEMENT(sniSub, tls13_extSubList_t, listLen, offset, uint16_t) = strlen(dnsHostname);
                sniSub->listLen = tls13_htons(offset);
                memcpy(sniSub->listData, dnsHostname, offset); /* "dns.google.com" */
                offset += sizeof(uint16_t);
                offset += sizeof(uint8_t);
            }
            //tempLen = tls13_htons(offset);//sizeof(tls13_extSubList_t) + offset;
            extSni->subListSize = tls13_htons(offset); //0xDCCD;
            tempLen = offset + sizeof(uint16_t);
            extSni->extDataLen = tls13_htons(tempLen); //0xAFAF;
            /* Update the total extension length so far */
            tempLen +=  sizeof(uint16_t) + sizeof(uint16_t);
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        offsetExt += offset;
        offset = 0;       
        {
            /* Set the EC Point Formats extension data */
            tls13_extension2211_t *ecPF = (tls13_extension2211_t *)((uint8_t *)&cExts->extECP + offsetExt);
            ecPF->extType = tls13_htons(TLS13_EXT_EC_POINTS_FORMAT);
            uint8_t *ecPFList = (uint8_t *)&ecPF->list[0];
            {
                ecPFList[0] = TLS13_EC_POINT_UNCOMPRESSED;
                ecPFList[1] = TLS13_EC_POINT_ANSIX962_COMPRESSED_PRIME;
                ecPFList[2] = TLS13_EC_POINT_ANSIX962_COMPRESSED_CHAR2;
                offset += 3;
            }
            ecPF->subListSize = offset;
            tempLen = offset + sizeof(ecPF->subListSize);
            ecPF->extDataLen = tls13_htons(tempLen);

            tempLen += sizeof(ecPF->extDataLen) + sizeof(ecPF->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        offsetExt += offset;
        offset = 0; 
        {
            /* Set the supported Group extension data */
            tls13_extension2222_t *supGr = (tls13_extension2222_t *)((uint8_t *)&cExts->extSupprotedGrp + offsetExt);
            supGr->extType = tls13_htons(TLS13_EXT_SUPPORTED_GROUPS);
            uint16_t *supGrList = (uint16_t *)&supGr->list[0];
            {
                supGrList[0] = tls13_htons(TLS13_SUPPGRP_X25519);
                supGrList[1] = tls13_htons(TLS13_SUPPGRP_SECP256R1);
                supGrList[2] = tls13_htons(TLS13_SUPPGRP_X448);
                supGrList[3] = tls13_htons(TLS13_SUPPGRP_SECP521R1);
                supGrList[4] = tls13_htons(TLS13_SUPPGRP_SECP384R1);
                supGrList[5] = tls13_htons(TLS13_SUPPGRP_FFDHE2048);
                supGrList[6] = tls13_htons(TLS13_SUPPGRP_FFDHE3072);
                supGrList[7] = tls13_htons(TLS13_SUPPGRP_FFDHE4096);
                supGrList[8] = tls13_htons(TLS13_SUPPGRP_FFDHE6144);
                supGrList[9] = tls13_htons(TLS13_SUPPGRP_FFDHE8192);
                offset = 10 * 2;
            }
            supGr->subListSize = tls13_htons(offset); /* each entry of 2 Bytes */
            tempLen = offset + sizeof(supGr->subListSize);
            supGr->extDataLen = tls13_htons(tempLen);
            tempLen += sizeof(supGr->extDataLen) + sizeof(supGr->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        offsetExt += offset;
        offset = 0;
        {
            /* set the Session Ticket extension data */
            tls13_extensionNULL_t *sesTic = (tls13_extensionNULL_t *)((uint8_t *)&cExts->extSessionTicket + offsetExt);
            sesTic->extType = tls13_htons(TLS13_EXT_SESSION_TICKET);
            sesTic->extDataLen = tls13_htons(0x0000);
            tempLen = sizeof(sesTic->extDataLen) + sizeof(sesTic->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        {
            /* Set the Encrypt-Then-MAC extension data */
            tls13_extensionNULL_t *enTM = (tls13_extensionNULL_t *)((uint8_t *)&cExts->extEncryptThenMAC + offsetExt);
            enTM->extType = tls13_htons(TLS13_EXT_ENCRYPT_THEN_MAC);
            enTM->extDataLen = tls13_htons(0x0000);
            tempLen = sizeof(enTM->extDataLen) + sizeof(enTM->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        {
            /* Set the extended master secret */
            tls13_extensionNULL_t *extMS = (tls13_extensionNULL_t *)((uint8_t *)&cExts->extExtendedMasterSecret + offsetExt);
            extMS->extType = tls13_htons(TLS13_EXT_EXT_MASTER_SECRET);
            extMS->extDataLen = tls13_htons(0x0000);
            tempLen = sizeof(extMS->extDataLen) + sizeof(extMS->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        {
            /* Set the Signature Algorithms Extension data */  
            tls13_extension2222_t *sigAlg = (tls13_extension2222_t *)((uint8_t *)&cExts->extSignatureAlgos + offsetExt);
            sigAlg->extType = tls13_htons(TLS13_EXT_SIGN_AGLORITHM);
            uint16_t *sigAlgList = (uint16_t *)&sigAlg->list[0];
            {
                sigAlgList[0] = tls13_htons(TLS13_SIGNALGOS_ECDSA_SECP256r1_SHA256);
                sigAlgList[1] = tls13_htons(TLS13_SIGNALGOS_ECDSA_SECP384r1_SHA384);
                sigAlgList[2] = tls13_htons(TLS13_SIGNALGOS_ECDSA_SECP521r1_SHA512);
                sigAlgList[3] = tls13_htons(TLS13_SIGNALGOS_ED25519);
                sigAlgList[4] = tls13_htons(TLS13_SIGNALGOS_ED448);
                sigAlgList[5] = tls13_htons(TLS13_SIGNALGOS_RSA_PSS_PSS_SHA256);
                sigAlgList[6] = tls13_htons(TLS13_SIGNALGOS_RSA_PSS_PSS_SHA384);
                sigAlgList[7] = tls13_htons(TLS13_SIGNALGOS_RSA_PSS_PSS_SHA512);
                sigAlgList[8] = tls13_htons(TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA256);
                sigAlgList[9] = tls13_htons(TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA384);
                sigAlgList[10] = tls13_htons(TLS13_SIGNALGOS_RSA_PSS_RSAE_SHA512);
                sigAlgList[11] = tls13_htons(TLS13_SIGNALGOS_RSA_PKCS1_SHA256);
                sigAlgList[12] = tls13_htons(TLS13_SIGNALGOS_RSA_PKCS1_SHA384);
                sigAlgList[13] = tls13_htons(TLS13_SIGNALGOS_RSA_PKCS1_SHA512);
                offset = 14 * 2;
            }
            sigAlg->subListSize = tls13_htons(offset);
            tempLen = offset + sizeof(sigAlg->subListSize);
            sigAlg->extDataLen = tls13_htons(tempLen);
            tempLen += sizeof(sigAlg->extType) + sizeof(sigAlg->extDataLen);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        offsetExt += offset;
        offset = 0;
        {
            /* Set the supported versions extension data */
            tls13_extension2212_t *supVers = (tls13_extension2212_t *)((uint8_t *)&cExts->extSupportedVers + offsetExt);
            supVers->extType = tls13_htons(TLS13_EXT_SUPPORTED_VERSIONS);
            uint16_t *supVersList = (uint16_t *)&supVers->list;
            {
                supVersList[0] = tls13_htons(TLS13_VERSION);
                offset = 1 * 2;
            }
            supVers->subListSize = offset;
            tempLen = offset + sizeof(supVers->subListSize);
            supVers->extDataLen = tls13_htons(tempLen);
            tempLen += sizeof(supVers->extDataLen) + sizeof(supVers->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        offsetExt += offset;
        offset = 0;       
        {
            /* Set the PSK Key exchange modes extension data */
            tls13_extension2211_t *pskKE = (tls13_extension2211_t *)((uint8_t *)&cExts->extPSKExchangeModes + offsetExt);
            pskKE->extType = tls13_htons(TLS13_EXT_PSK_KEYXCHANGE_MODES);
            uint8_t *pskKEList = (uint8_t *)&pskKE->list;
            {
                pskKEList[0] = 1; /* 01 - assigned value for "PSK with (EC)DHE key establishment */
                offset = 1 * 1;
            }
            pskKE->subListSize = offset;
            tempLen = offset + sizeof(pskKE->subListSize);
            pskKE->extDataLen = tls13_htons(tempLen);
            tempLen += sizeof(pskKE->extDataLen) + sizeof(pskKE->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
        }
        offsetExt += offset;
        offset = 0;              
        {
            /* Set the key share extension data */
            tls13_extensionKeyShare_t *keyS = (tls13_extensionKeyShare_t *)((uint8_t *)&cExts->extkeyShare + offsetExt);
            keyS->extType = tls13_htons(TLS13_EXT_KEY_SHARE);
            keyS->keyShareType = tls13_htons(TLS13_SUPPGRP_X25519); /* assigned value for x25519 (key exchange via curve25519) */
            {
                memcpy(keyS->pubKey, pubKey, pubKeyLen);
                offset += pubKeyLen;
            }
            tempLen = offset + sizeof(keyS->keyShareType) + sizeof(keyS->pubKeyLen);
            keyS->keyShareLen = tls13_htons(tempLen); /* key share data length */
            keyS->pubKeyLen = tls13_htons(pubKeyLen);  /* 32  Bytes of public key */
            tempLen += sizeof(keyS->keyShareLen);
            keyS->extDataLen = tls13_htons(tempLen);
            tempLen += sizeof(keyS->extDataLen) + sizeof(keyS->extType);
            /* Update the total extension length so far */
            REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) += tempLen;
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
                                                        REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t);
    clientHelloTmp->handshakeHeader.handshakeMsgLen = tls13_htonss(handshakeLen);
                                                        
    recordLen = handshakeLen + sizeof(tls13_handshakeHdr_t);

    clientHelloTmp->recordHeader.recordLen = tls13_htons(recordLen);

    tempLen = REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t);
    REACH_ELEMENT(clientHelloTmp, tls13_clientHello_t, extLen, TLS13_CLIENT_EXT_OFFSET, uint16_t) = tls13_htons(tempLen);

    /* Finally do a memcopy */
    len = recordLen + TLS13_RECORD_HEADER_SIZE;
    memcpy(tlsPkt, (uint8_t *)clientHelloTmp, len);

    free(clientHelloTmp);
    return len;
}

void tls13_extractClientHello(uint8_t *clientRandom, uint8_t *sessionId, uint8_t *dnsHostname, tls13_capability_t *capability,
                                    uint16_t *keyType, uint8_t *pubKey, uint16_t *pubKeyLen, const uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t tempLen;
    uint8_t idx;
    uint16_t len = (((tlsPkt[3] & 0xFFFF) << 8) | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE; // change endianess while reading
    tls13_clientHello_t *cHello = calloc(1, len);
    memcpy(cHello, tlsPkt, len);

    printf("client Hello received length: %d + %d: %d\n", tlsPkt[4], tlsPkt[3], len);
    printf("record Type: %d\n", cHello->recordHeader.recordType);
    assert(cHello->recordHeader.recordType == TLS13_HANDSHAKE_RECORD);
    assert(tls13_ntohs(cHello->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
    assert(cHello->handshakeHeader.handshakeType == TLS13_HST_CLIENT_HELLO);
    assert(tls13_ntohs(cHello->clientVersion) == TLS12_PROTO_VERSION);

    memcpy(clientRandom, cHello->clientRandom, TLS13_RANDOM_LEN);
    memcpy(sessionId, cHello->sessionId, cHello->sessionIdLen);
    offset += cHello->sessionIdLen;

    /* copy the supported cipher suite list to the local buffer */
    tempLen = tls13_ntohs(REACH_ELEMENT(cHello, tls13_clientHello_t, cipherSuiteLen, offset, uint16_t));
    printf("cipher Suite Length: %d\n", tempLen);
    if(tempLen > 0){
        tls13_cipherSuiteData_t *csd = (tls13_cipherSuiteData_t *)((uint8_t *)&cHello->cipherSuiteList[0] + offset);
        //printf("%lx : %lx --> cipher suite list address {address:%lx, offset %lx}\n", cHello, csd, &cHello->cipherSuiteList[0], offset);
        memcpy(capability->cipherSuiteList, csd, tempLen);
        /*for(idx = 0; idx < (tempLen/2); idx++){
            capability->cipherSuiteList[idx] = csd[idx];
        }*/
        capability->cipherSuiteLen = tempLen;
        offset += tempLen;
    }
    /* Copy the supported compression menthod list to the local buffer */
    tempLen = REACH_ELEMENT(cHello, tls13_clientHello_t, compressionMethodLen, offset, uint8_t);
    if(cHello->compressionMethodLen > 0){
        tls13_compressionMethods_t *cml= ((uint8_t *)&cHello->compressionMethodList[0] + offset);
        memcpy(capability->compressionMethodList, cml, tempLen);
        capability->compressionMethodLen = tempLen;
        offset += tempLen;
    }

    tls13_clientExtensions_t *ext = (tls13_clientExtensions_t *)((uint8_t *)&cHello->clientExt + offset);
    printf("%lx + %lx----> %lx\n",&cHello->clientExt, offset,  ext);
    offset = 0;
    {
        /* Server Name Indication (SNI) Extension */
        tls13_extensionSNI_t *sni = &ext->extSNI;
        #ifdef DEBUG
        for(int i = 90; i < 120; i++){
            printf("[%lx --> %d]: [%lx --> %d]", ((uint8_t *)sni + i - 90), *((uint8_t *)sni + i - 90), ((uint8_t *)cHello + i), *((uint8_t *)cHello + i));
            printf("\n");
        }
        #endif
        assert(tls13_ntohs(sni->extType) == TLS13_EXT_SERVER_NAME); /* should be hostname - macro needed */
        printf("%lx : %lx : %lx --> Server Name Indication {address:%lx, offset:%lx}\n", cHello, ext, sni, sni, offset);
        {
            tls13_extSubList_t *subList = &sni->list[0];
            assert(subList->listType == 0x00); /* should be server name - macro needed */
            assert(subList->listLen > 0x00);
            tempLen = tls13_ntohs(subList->listLen);
            printf("Hostname Length: %d\n", tempLen);
            memcpy(capability->hostname, sni->list->listData, tempLen);
            capability->hostnameLen = tempLen;
            #ifdef DEBUG
            for(int i = 0; i < tempLen; i++){
                printf("[%d] %x - %x\n", i, sni->list->listData[i], capability->hostname[i]);
            }
            #endif
        }
        printf("extension type: %d, sublist size: %d, list length: %d\n", tls13_ntohs(sni->extType), tls13_ntohs(sni->subListSize), tempLen);
        offset += tls13_ntohs(sni->subListSize);
                  
        /* EC Point Formats extension */
        tls13_extension2211_t *ecp = (tls13_extension2211_t *)((uint8_t *)&ext->extECP + offset);
        printf("%lx : %lx : %lx --> EC Points Format {address:%lx, offset:%lx}\n", cHello, ext, ecp, (uint8_t *)&ext->extECP, offset);
        printf("extension type: %d\n", tls13_ntohs(ecp->extType));
        assert(tls13_ntohs(ecp->extType) == TLS13_EXT_EC_POINTS_FORMAT);
        tempLen = ecp->subListSize;
        memcpy(capability->ecPoints, ecp->list, tempLen);
        capability->ecFormatsLen = tempLen;
        offset += tempLen;

        /* Supported Groups Extension */               
        tls13_extension2222_t *sgr = (tls13_extension2222_t *)((uint8_t *)&ext->extSupprotedGrp + offset);
        printf("extension type: %d\n", tls13_ntohs(sgr->extType));
        assert(tls13_ntohs(sgr->extType) == TLS13_EXT_SUPPORTED_GROUPS);
        tempLen = tls13_ntohs(sgr->subListSize);
        memcpy(capability->supportedGrp, sgr->list, tempLen);
        capability->supportedGrpLen = tempLen;
        offset += tempLen;

        /* extension data length is 0 - session ticket */         
        tls13_extensionNULL_t *stkt = (tls13_extensionNULL_t *)((uint8_t *)&ext->extSessionTicket + offset);
        assert(tls13_ntohs(stkt->extType) == TLS13_EXT_SESSION_TICKET);
        if(tls13_ntohs(stkt->extDataLen) > 0x0000){
            /* To be handled */
        }

        /* extension data length is 0 - Encrypt-Then-MAC */         
        tls13_extensionNULL_t *etm = (tls13_extensionNULL_t *)((uint8_t *)&ext->extEncryptThenMAC + offset);
        assert(tls13_ntohs(etm->extType) == TLS13_EXT_ENCRYPT_THEN_MAC);
        if(tls13_ntohs(etm->extDataLen) > 0x0000){
            /* To be handled */
        }

        /* extension data length is 0 - extended master secret */       
        tls13_extensionNULL_t *ems = (tls13_extensionNULL_t *)((uint8_t *)&ext->extExtendedMasterSecret + offset);
        assert(tls13_ntohs(ems->extType) == TLS13_EXT_EXT_MASTER_SECRET);
        if(tls13_ntohs(ems->extDataLen) > 0x0000){
            /* to be handled */
        }

        /* Signature Algorithms Extension */
        tls13_extension2222_t *esa = (tls13_extension2222_t *)((uint8_t *)&ext->extSignatureAlgos + offset);
        assert(tls13_ntohs(esa->extType) == TLS13_EXT_SIGN_AGLORITHM);
        tempLen = tls13_ntohs(esa->subListSize);
        memcpy(capability->signAlgos, esa->list, tempLen);
        capability->signAlgoLen = tempLen;
        offset += tempLen;

        /* supported versions */       
        tls13_extension2212_t *esv = (tls13_extension2212_t *)((uint8_t *)&ext->extSupportedVers + offset);
        assert(tls13_ntohs(esv->extType) == TLS13_EXT_SUPPORTED_VERSIONS);
        tempLen = esv->subListSize;
        memcpy(capability->supportedVersions, esv->list, tempLen);
        capability->supportedVersionLen = tempLen;
        offset += tempLen;

        /* PSK key exchange modes */
        tls13_extension2211_t *epskkem = (tls13_extension2211_t *)((uint8_t *)&ext->extPSKExchangeModes + offset);
        printf("extension type: %d\n", tls13_ntohs(epskkem->extType));
        assert(tls13_ntohs(epskkem->extType) == TLS13_EXT_PSK_KEYXCHANGE_MODES);
        assert(epskkem->list[0] == 1); /* 01 - assigned value for "PSK with (EC)DHE key establishment */
        tempLen = epskkem->subListSize;
        assert(tempLen == 1);
        memcpy(capability->keyXchangeModes, epskkem->list, tempLen);
        capability->keyXchangeModesLen = tempLen;
        offset += tempLen;

        /* Key share */
        tls13_extensionKeyShare_t *ks = (tls13_extensionKeyShare_t *)((uint8_t *)&ext->extkeyShare + offset);
        assert(tls13_ntohs(ks->extType) == TLS13_EXT_KEY_SHARE);
        //assert(tls13_ntohs(ks->keyShareType) == 0x001D); /* assigned value for x25519 (key exchange via curve25519) */
        //assert(tls13_ntohs(ks->keyShareLen) == 2);
        keyType = tls13_ntohs(ks->keyShareType);
        pubKeyLen = tls13_ntohs(ks->keyShareLen);
        memcpy(pubKey, ks->pubKey, pubKeyLen);
    }
}

uint16_t tls13_prepareServerHello(const uint8_t *serverRandom, const uint8_t *sessionId, const tls13_cipherSuite_e cipherSuite, 
                                    const uint8_t *pubKey, const uint16_t pubKeyLen, const uint16_t keyType, const uint8_t *extData, const uint16_t extDataLen, 
                                    uint8_t *tlsPkt)
{
    uint16_t len = 0;
    uint16_t offset = 0;
    uint16_t tempLen = 0;
    //tls13_cipherSuite_e cs = tls13_getCipherSuite();
    tls13_serverHellowCompat_t *serverHelloTmp = calloc(1, (sizeof(tls13_serverHellowCompat_t) + 1200));
    printf("serverHello temp -> %lx\n", serverHelloTmp);

    /* Record header update */
    serverHelloTmp->serverHello.recordHeader.recordType   = TLS13_HANDSHAKE_RECORD;
    serverHelloTmp->serverHello.recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION);

    /* handshake header update */
    serverHelloTmp->serverHello.handshakeHeader.handshakeType = TLS13_HST_SERVER_HELLO;

    serverHelloTmp->serverHello.serverVersion = tls13_htons(TLS12_PROTO_VERSION);
    /* get a 32 Byte random value */
    memcpy(serverHelloTmp->serverHello.serverRandom, serverRandom, TLS13_RANDOM_LEN);
    serverHelloTmp->serverHello.sessionIdLen = TLS13_SESSION_ID_LEN;
    /* Get a 32 Byte Session Id */
    memcpy(serverHelloTmp->serverHello.sessionId, sessionId, TLS13_SESSION_ID_LEN);

    /* copy the Ciphersuite selected */
    //serverHelloTmp->serverHello.cipherSuiteSelect = cipherSuite;//TLS13_AES_128_GCM_SHA256;
    SERVERHELLO_CIPHERSUITE_SELECT(&serverHelloTmp->serverHello.cipherSuiteSelect, TLS13_SESSION_ID_LEN) = tls13_htons(cipherSuite); //0xCCDD;
    /* copy the compression methods */
    SERVERHELLO_COMPRESSION_METHOD_SELECT(&serverHelloTmp->serverHello.compressionMethodSelect, TLS13_SESSION_ID_LEN) = 0x00U;//0xBB;

    uint16_t extLen = 0;

    /* Server Hello Extensions */
    {
        tls13_serverExtensions_t *serverExts = GET_SERVERHELLO_SERVEREXT_PTR(&serverHelloTmp->serverHello.serverExt, TLS13_SESSION_ID_LEN);
        {
            tls13_extension222_t  *eSV = &serverExts->extSupportedVers;
            eSV->extType = tls13_htons(TLS13_EXT_SUPPORTED_VERSIONS);
            eSV->extData = tls13_htons(TLS13_VERSION);
            eSV->extDataLen = tls13_htons(sizeof(eSV->extData));
            extLen += sizeof(tls13_extension222_t);
        }
        {
            tls13_extensionKeyShare_t  *eKS = &serverExts->extkeyShare;
            eKS->extType = tls13_htons(TLS13_EXT_KEY_SHARE);
            eKS->keyShareType = tls13_htons(keyType);//0x001D; /* assigned value for x25519 (key exchange via curve25519) */
            memcpy(eKS->pubKey, pubKey, pubKeyLen);
            eKS->keyShareLen = tls13_htons(sizeof(eKS->keyShareType)); /* 2 Bytes of key share Type code */
            eKS->pubKeyLen = tls13_htons(pubKeyLen);  /* 32  Bytes of public key */
            tempLen = sizeof(eKS->keyShareType) + sizeof(eKS->keyShareLen) + pubKeyLen;
            eKS->extDataLen = tls13_htons(tempLen);
            extLen += tempLen + sizeof(eKS->extType) + sizeof(eKS->extDataLen);
        }
    }
    SERVERHELLO_SERVEREXT_LEN(&serverHelloTmp->serverHello, TLS13_SESSION_ID_LEN) = tls13_htons(extLen);
    tempLen = sizeof(serverHelloTmp->serverHello) + TLS13_SESSION_ID_LEN + pubKeyLen - TLS13_RECORD_HEADER_SIZE - sizeof(tls13_handshakeHdr_t);
    serverHelloTmp->serverHello.handshakeHeader.handshakeMsgLen = tls13_htonss(tempLen);
    tempLen = tempLen + sizeof(tls13_handshakeHdr_t);
    serverHelloTmp->serverHello.recordHeader.recordLen = tls13_htons(tempLen);

    /* Fill and serialize the change cipher spec structure */
    tls13_changeCipherSpec_t *sCCS = (tls13_changeCipherSpec_t *)((uint8_t *)&serverHelloTmp->serverCCS + TLS13_SESSION_ID_LEN + pubKeyLen);
    {
        sCCS->recordHeader.recordType   = TLS13_CHANGE_CIPHERSPEC_RECORD;
        sCCS->recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION); /* Legacy TLS 1.2 */
        sCCS->payload                   = 0x01;
        sCCS->recordHeader.recordLen    = tls13_htons(0x0001);
    }

    /* Fill and serialize the first wrapped record with encrypted data */
    tls13_wrappedRecord_t *rec = (tls13_wrappedRecord_t *)((uint8_t *)&serverHelloTmp->record1 + TLS13_SESSION_ID_LEN + pubKeyLen);
    {
        rec->recordHeader.recordType = TLS13_APPDATA_RECORD;
        rec->recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION); /* legacy TLS 1.2 */
  
        tls13_encryExt_t *dataTmp = calloc(1, 100);
        {
            dataTmp->handshakeHdr.handshakeType = TLS13_HST_ENCRYPTED_EXT;
            tempLen = extDataLen;
            dataTmp->extLen = tls13_htons(tempLen);
            tempLen += sizeof(dataTmp->extLen);
            dataTmp->handshakeHdr.handshakeMsgLen = tls13_htonss(tempLen);
            if(extDataLen > 0){
                memcpy(&dataTmp->extList, extData, extDataLen);
            }
            REACH_ELEMENT(dataTmp, tls13_encryExt_t, recordType, extDataLen, uint8_t) = TLS13_HANDSHAKE_RECORD;
        }
  
        tls13_encrypt((uint8_t *)dataTmp, (sizeof(tls13_encryExt_t) + extDataLen), &rec->encryptedData, cipherSuite);
        //memcpy(rec->encryptedData, dataTmp, dataLen);     /* encrypted data with server handshake key */
        //memcpy(rec->authTag + dataLen, authTag, TLS13_RECORD_AUTHTAG_LEN);      /* 16 Byte auth tag */
        len = sizeof(tls13_serverHello_t) + TLS13_SESSION_ID_LEN + pubKeyLen + sizeof(tls13_changeCipherSpec_t) + \
                sizeof(tls13_encryExt_t) + extDataLen - TLS13_RECORD_AUTHTAG_LEN;
        tls13_generate_authTag((uint8_t *)serverHelloTmp, len, (rec->authTag + sizeof(tls13_encryExt_t) + extDataLen), TLS13_RECORD_AUTHTAG_LEN, cipherSuite);
        tempLen = sizeof(tls13_wrappedRecord_t) + sizeof(tls13_encryExt_t) + extDataLen - TLS13_RECORD_HEADER_SIZE;
        rec->recordHeader.recordLen = tls13_htons(tempLen);
        free(dataTmp);
    }
    len = tls13_ntohs(serverHelloTmp->serverHello.recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE + \
                                                                tls13_ntohs(sCCS->recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE + \
                                                                tls13_ntohs(rec->recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE;
    /* Finally do a memory copy */
    memcpy(tlsPkt, (uint8_t *)serverHelloTmp, len);
    //printf("serverHello temp -> %lx\n", serverHelloTmp);
    free(serverHelloTmp);

    return len;
}

void tls13_extractServerHello(uint8_t *serverRandom, uint8_t *sessionId, uint16_t *cipherSuite, 
                                    uint8_t *pubKey, uint16_t *pubKeyLen, uint16_t *keyType, uint8_t *encryExt, uint16_t *encryExtLen, const uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t tempLen = 0;
    //tls13_cipherSuite_e cs = tls13_getCipherSuite();
    uint16_t helloLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t changeCSLen = ((uint16_t)tlsPkt[helloLen + 3] << 8 | tlsPkt[helloLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t appDataLen = ((uint16_t)tlsPkt[helloLen + changeCSLen + 3] << 8 | tlsPkt[helloLen + changeCSLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tempLen = helloLen + changeCSLen + appDataLen;
    tls13_serverHellowCompat_t *tmp = calloc(1, tempLen);
    memcpy(tmp, tlsPkt, tempLen);
    {
        tls13_serverHello_t *sHello = &tmp->serverHello;
        assert(sHello->recordHeader.recordType == TLS13_HANDSHAKE_RECORD);
        assert(tls13_ntohs(sHello->recordHeader.protoVersion) == TLS12_PROTO_VERSION || tls13_ntohs(sHello->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
        assert(tls13_ntohs(sHello->serverVersion) == TLS12_PROTO_VERSION);
        memcpy(serverRandom, sHello->serverRandom, TLS13_RANDOM_LEN);
        memcpy(sessionId, sHello->sessionId, sHello->sessionIdLen);
        offset += sHello->sessionIdLen;
        *cipherSuite = tls13_ntohs(REACH_ELEMENT(sHello, tls13_serverHello_t, cipherSuiteSelect, offset, uint16_t));
        //REACH_ELEMENT(sHello, tls13_serverHello_t, compressionMethodSelect, offset, uint16_t);
        tls13_serverExtensions_t *serExt = (tls13_serverExtensions_t *)((uint8_t *)&sHello->serverExt + offset);
        {
            assert(tls13_ntohs(serExt->extSupportedVers.extType) == TLS13_EXT_SUPPORTED_VERSIONS);
            assert(tls13_ntohs(serExt->extSupportedVers.extData) == TLS13_VERSION);
            assert(tls13_ntohs(serExt->extSupportedVers.extDataLen) == 2);
            assert(tls13_ntohs(serExt->extkeyShare.extType) == TLS13_EXT_KEY_SHARE);
            *keyType = tls13_ntohs(serExt->extkeyShare.keyShareType);
            *pubKeyLen = tls13_ntohs(serExt->extkeyShare.pubKeyLen);
            memcpy(pubKey, serExt->extkeyShare.pubKey, *pubKeyLen);
            offset += tls13_ntohs(serExt->extkeyShare.pubKeyLen);
        }
    }
    /* Server change cipher spec */
    {
        tls13_changeCipherSpec_t *ccs = (tls13_changeCipherSpec_t *)((uint8_t *)&tmp->serverCCS + offset);
        assert(ccs->recordHeader.recordType == TLS13_CHANGE_CIPHERSPEC_RECORD);
        assert(tls13_ntohs(ccs->recordHeader.protoVersion) == TLS12_PROTO_VERSION || tls13_ntohs(ccs->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
        assert(ccs->payload == 0x01);
        assert(tls13_ntohs(ccs->recordHeader.recordLen) == 0x0001);
    }
    /* Server encrypted extension */
    {
        tls13_wrappedRecord_t *data = (tls13_wrappedRecord_t *)((uint8_t *)&tmp->record1 + offset);
        assert(data->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(tls13_ntohs(data->recordHeader.protoVersion) == TLS12_PROTO_VERSION || tls13_ntohs(data->recordHeader.protoVersion) == TLS13_PROTO_VERSION);

        uint16_t dataLen = tls13_ntohs(data->recordHeader.recordLen) - TLS13_RECORD_AUTHTAG_LEN;
        tls13_encryExt_t *dataTmp = calloc(1, dataLen);
        {
            tls13_decrypt((uint8_t *)data->encryptedData, dataLen, (uint8_t *)dataTmp, *cipherSuite);
            assert(dataTmp->handshakeHdr.handshakeType == TLS13_HST_ENCRYPTED_EXT);

            uint16_t encryExtLenTmp = dataTmp->extLen;
            if(encryExtLenTmp)
            {
                memcpy(encryExt, dataTmp->extList, encryExtLenTmp);
            }
            *encryExtLen = encryExtLenTmp;
        }
        free(dataTmp);
        /* Generate Mac of the received encrypted data */
        assert(true == tls13_verify_authTag(data->encryptedData, dataLen, data->authTag + dataLen, TLS13_RECORD_AUTHTAG_LEN, *cipherSuite));
    }
    free(tmp);
}

uint16_t tls13_prepareServerWrappedRecord(const uint8_t *dCert, const uint16_t dCertLen, 
                                        const uint8_t *dCertVerf, const uint16_t dCertVerfLen, 
                                        const uint8_t *dVerify, const uint16_t dVerifyLen, tls13_cipherSuite_e cs, 
                                        tls13_signAlgos_e signType, uint8_t *tlsPkt)
{
    uint32_t len = 0;
    uint16_t offset = 0;
    uint32_t tempLen = 0;
    tempLen = sizeof(tls13_serverWrappedRecord_t) + dCertLen + dCertVerfLen + dVerifyLen;
    tls13_serverWrappedRecord_t *record = calloc(1, tempLen); //need to fix magic numbers

    // should be able to send certificate request, if certificate is expected from the client
    /* certificate */
    tls13_certRecord_t *certRecord = &record->certRecord;
    {
        uint16_t certRecordLen = 0;
        certRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        certRecord->recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION); /* Legacy TLS 1.2 */

        tls13_certRecordDataDecrypt_t *certR = calloc(1, (dCertLen + sizeof(tls13_certRecordDataDecrypt_t) + sizeof(tls13_cert_t)));
        {
            certR->certificate.handshakeHdr.handshakeType = TLS13_HST_CERTIFICATE;
            certR->certificate.requestContext = 0x00;
            tls13_cert_t *cert = &certR->certificate.cert;
            {
                tempLen = dCertLen;
                cert->certLen = tls13_htonss(tempLen);
                memcpy(cert->cert, dCert, dCertLen);
                REACH_ELEMENT(cert, tls13_cert_t, certExtLen, dCertLen, uint16_t) = tls13_htons(0x0000);
                if(cert->certExtLen > 0){
                    #if CERT_EXT_SUPPORTED
                        /* copy extension data */
                    #endif
                }
                offset = (dCertLen + sizeof(tls13_cert_t));
            }
            //certR->recordType = TLS13_HANDSHAKE_RECORD;
            tempLen = dCertLen + sizeof(tls13_cert_t);
            certR->certificate.payloadLen = tls13_htonss(tempLen);
            tempLen += (sizeof(certR->certificate.requestContext) + TLS13_HANDSHAKE_LENGTH_FIELD_SIZE);
            certR->certificate.handshakeHdr.handshakeMsgLen = tls13_htonss(tempLen);
            certRecordLen = tempLen + TLS13_HANDSHAKE_HEADER_SIZE;
            REACH_ELEMENT(certR, tls13_certRecordDataDecrypt_t, recordType, offset, uint8_t) = TLS13_HANDSHAKE_RECORD; /* this can't be seen in pkt */
        }
        /* Encrypt the data before copying */
        tls13_encrypt((uint8_t *)certR, certRecordLen, (uint8_t *)certRecord->encryptedData, cs);  // encrypted data length to be standardised. data encrypted with the server handshake key
        offset = certRecordLen + sizeof(certR->recordType);
        tempLen = offset + TLS13_RECORD_AUTHTAG_LEN;
        certRecord->recordHeader.recordLen = tls13_htons(tempLen);
        tempLen += (TLS13_RECORD_HEADER_SIZE - TLS13_RECORD_AUTHTAG_LEN);
        //memcpy(certRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(certRecord, tempLen, ((uint8_t*)&certRecord->authTag[0] + offset), TLS13_RECORD_AUTHTAG_LEN, cs); 

        /* Number of bytes so far */
        len += (tempLen + TLS13_RECORD_AUTHTAG_LEN);
        free(certR);
    }
    tempLen = 0;
    /* certificate verification */
    tls13_certVerifyRecord_t *certVerifyRecord = (tls13_certVerifyRecord_t *)((uint8_t *)&record->certVerifyRecord + offset); 
    {
        certVerifyRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        certVerifyRecord->recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION); /* Legacy TLS 1.2 */

        tls13_certVerifyRecordDataDecrypt_t *certVerif = calloc(1, (dCertVerfLen + sizeof(tls13_certVerifyRecordDataDecrypt_t)));
        {
            certVerif->certVerify.handshakeHdr.handshakeType = TLS13_HST_CERTIFICATE_VERIFY;
            tempLen = dCertVerfLen + sizeof(tls13_signature_t);
            certVerif->certVerify.handshakeHdr.handshakeMsgLen = tls13_htonss(tempLen);

            /* Encrypt the data before copying */
            certVerif->certVerify.sign.signType = tls13_htons(signType);
            certVerif->certVerify.sign.signLen = tls13_htons(dCertVerfLen);
            memcpy(certVerif->certVerify.sign.sign, dCertVerf, dCertVerfLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
            tempLen = dCertVerfLen + sizeof(tls13_signature_t) + sizeof(certVerif->recordType) + TLS13_HANDSHAKE_HEADER_SIZE;
            offset += tempLen;
            REACH_ELEMENT(certVerif, tls13_certVerifyRecordDataDecrypt_t, recordType, dCertVerfLen, uint8_t) = TLS13_HANDSHAKE_RECORD;
            tls13_encrypt((uint8_t *)certVerif, tempLen, (uint8_t *)certVerifyRecord->encryptedData, cs);
        }
        //memcpy(certVerifyRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tempLen += (TLS13_RECORD_AUTHTAG_LEN);
        //REACH_ELEMENT(&certVerifyRecord->recordHeader, tls13_recordHdr_t, recordLen, tempLen, uint16_t) = tls13_htons(tempLen);
        certVerifyRecord->recordHeader.recordLen = tls13_htons(tempLen);
        tempLen += (TLS13_RECORD_HEADER_SIZE - TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(certVerifyRecord, tempLen, \
              ((uint8_t *)&certVerifyRecord->authTag[0] + dCertVerfLen + sizeof(tls13_signature_t) + TLS13_HANDSHAKE_HEADER_SIZE + sizeof(certVerif->recordType)), \
              TLS13_RECORD_AUTHTAG_LEN, cs);
        /* Number of Bytes so far */
        len += (tempLen + TLS13_RECORD_AUTHTAG_LEN);
        free(certVerif);
    }
    tempLen = 0;
    tls13_finishedRecord_t *finishedRecord = (tls13_finishedRecord_t *)((uint8_t *)&record->finishedRecord + offset);
    {
        finishedRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = TLS12_PROTO_VERSION; /* Legacy TLS 1.2 */
        
        tsl13_finishedRecordDataDecrypted_t *verf = calloc(1, (dVerifyLen + sizeof(tsl13_finishedRecordDataDecrypted_t)));
        {
            verf->finished.handshakeHdr.handshakeType = TLS13_HST_FINISHED;
            verf->finished.handshakeHdr.handshakeMsgLen = tls13_htonss(dVerifyLen);
            //verf->recordType = TLS13_HANDSHAKE_RECORD;
            /* Encrypt the data before copying */
            memcpy(verf->finished.verifyData, dVerify, dVerifyLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
            tempLen = sizeof(tsl13_finishedRecordDataDecrypted_t) + dVerifyLen;
            REACH_ELEMENT(verf, tsl13_finishedRecordDataDecrypted_t, recordType, dVerifyLen, uint8_t) = TLS13_HANDSHAKE_RECORD;
            tls13_encrypt((uint8_t *)verf, tempLen, (uint8_t *)finishedRecord->encryptedData, cs);
        }  
        tempLen += (TLS13_RECORD_AUTHTAG_LEN);
        //REACH_ELEMENT(&finishedRecord->recordHeader, tls13_recordHdr_t, recordLen, tempLen, uint16_t) = tls13_htons(tempLen);
        finishedRecord->recordHeader.recordLen = tls13_htons(tempLen);

        tempLen += (TLS13_RECORD_HEADER_SIZE - TLS13_RECORD_AUTHTAG_LEN);
        //memcpy(finishedRecord->authTag + offset, authTag, TLS13_RECORD_AUTHTAG_LEN);
        tls13_generate_authTag(finishedRecord, tempLen, ((uint8_t *)&finishedRecord->authTag[0] + dVerifyLen + sizeof(tsl13_finishedRecordDataDecrypted_t)), \
                               TLS13_RECORD_AUTHTAG_LEN, cs);
        /* NUmber of Bytes so far */
        len += (tempLen + TLS13_RECORD_AUTHTAG_LEN);
        free(verf);
    }

    memcpy(tlsPkt, (uint8_t *)record, len);
    free(record);
    return len;
}

void tls13_extractServerWrappedRecord(const uint8_t *tlsPkt, uint8_t *dCert, uint16_t *dCertLen, tls13_signature_t *sign, uint8_t *dVerify, uint16_t *dVerifyLen,
                                        tls13_cipherSuite_e cs, tls13_signAlgos_e signType)
{
    uint16_t authTagOffset = 0;
    uint16_t tempLen = 0; 
    uint16_t certLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t certVerfLen = ((uint16_t)tlsPkt[certLen + 3] << 8 | tlsPkt[certLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t verfLen = ((uint16_t)tlsPkt[certLen + certVerfLen + 3] << 8 | tlsPkt[certLen + certVerfLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    tempLen = certLen + certVerfLen + verfLen;
    printf("The cert Record length is %d; the cert verify record (signature) length is %d; the handshake verify length is %d \n", certLen, certVerfLen, verfLen);

    tls13_serverWrappedRecord_t *tmp = calloc(1, certLen + certVerfLen + verfLen);
    memcpy(tmp, tlsPkt, tempLen);

    if(tlsPkt[0] == TLS13_APPDATA_RECORD){
        printf("Certficate record found\n");
        tls13_certRecord_t *recvdCertRecord = (tls13_certRecord_t *)&tmp->certRecord;
        authTagOffset = tls13_ntohs(recvdCertRecord->recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE - TLS13_RECORD_AUTHTAG_LEN;
        tempLen = tls13_ntohs(recvdCertRecord->recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE - sizeof(tls13_certRecord_t);
        /* Some basic assertion to check for pkt deformity */
        assert(recvdCertRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(tls13_ntohs(recvdCertRecord->recordHeader.protoVersion) == TLS12_PROTO_VERSION || \
               tls13_ntohs(recvdCertRecord->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
        assert(true == tls13_verify_authTag(recvdCertRecord->encryptedData, authTagOffset, 
                                            (recvdCertRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));

        //tls13_certRecordDataDecrypt_t *dCertTemp = (tls13_certRecordDataDecrypt_t *)&recvdCertRecord->encryptedData;
        /* Get the size of certificate and allocate a temporaray memory */
        tls13_certRecordDataDecrypt_t *dCertTemp = calloc(1, tempLen);
        {
            tls13_decrypt((uint8_t *)recvdCertRecord->encryptedData, tempLen, (uint8_t *)dCertTemp, cs);
            //assert(dCertTemp->recordType == TLS13_HANDSHAKE_RECORD);
            assert(dCertTemp->certificate.handshakeHdr.handshakeType == TLS13_HST_CERTIFICATE);

            *dCertLen = tls13_ntohl(dCertTemp->certificate.cert->certLen);
            if(dCert != NULL){
                /* Certificate will be in ASN.1 DER encoding and unencrypted */
                memcpy(dCert, dCertTemp->certificate.cert->cert, *dCertLen);
            }
            //if(dCert->certExtLen != 0)
                //dCert->certExtension[0] = REACH_ELEMENT(dCertTemp->certificate.cert, tls13_cert_t, certExtension, dCert->certLen, uint16_t);
        }
        free(dCertTemp);
    }
    if(tlsPkt[certLen] == TLS13_APPDATA_RECORD)
    {
        printf("Certificate Verify record found\n");
        tls13_certVerifyRecord_t *recvdCertVerifyRecord = (tls13_certVerifyRecord_t *)((uint8_t *)&tmp->certVerifyRecord + certLen);
        authTagOffset = tls13_ntohs(recvdCertVerifyRecord->recordHeader.recordLen) - TLS13_RECORD_AUTHTAG_LEN;
        tempLen = tls13_ntohs(recvdCertVerifyRecord->recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE - sizeof(tls13_certVerifyRecord_t);
        assert(recvdCertVerifyRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(tls13_ntohs(recvdCertVerifyRecord->recordHeader.protoVersion) == TLS12_PROTO_VERSION || \
               tls13_ntohs(recvdCertVerifyRecord->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
        assert(true == tls13_verify_authTag(recvdCertVerifyRecord->encryptedData, tempLen, 
                                            (recvdCertVerifyRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));
        
        //tls13_certVerifyRecordDataDecrypt_t *dSign = (tls13_certVerifyRecordDataDecrypt_t *)&recvdCertVerifyRecord->encryptedData;
        tls13_certVerifyRecordDataDecrypt_t *dSign = calloc(1, certVerfLen);
        {
            /* The cert verify record is not encrypted as usual */
            //tls13_decrypt((uint8_t *)recvdCertVerifyRecord->encryptedData, certVerfLen, (uint8_t *)dSign, cs);
            memcpy((uint8_t *)dSign, (uint8_t *)recvdCertVerifyRecord->encryptedData, certVerfLen);
            assert(dSign->recordType == TLS13_HANDSHAKE_RECORD);
            assert(dSign->certVerify.handshakeHdr.handshakeType == TLS13_HST_CERTIFICATE_VERIFY);
            sign->signType = dSign->certVerify.sign.signType;
            sign->signLen = dSign->certVerify.sign.signLen;
            if(sign->sign != NULL){
                /* Signature would be on handshake hash and will be encrypted */
                memcpy(sign->sign, dSign->certVerify.sign.sign, sign->signLen);
            }
        }
        free(dSign);
    }
    if(tlsPkt[certLen + certVerfLen] == TLS13_APPDATA_RECORD)
    {
        printf("Server finished record found\n");
        tls13_finishedRecord_t *recvdFinRecord = (tls13_finishedRecord_t *)((uint8_t *)&tmp->finishedRecord + certLen + certVerfLen);
        authTagOffset = tls13_ntohs(recvdFinRecord->recordHeader.recordLen) - TLS13_RECORD_AUTHTAG_LEN;
        tempLen = tls13_ntohs(recvdFinRecord->recordHeader.recordLen) + TLS13_RECORD_HEADER_SIZE - sizeof(tls13_certVerifyRecord_t);
        assert(recvdFinRecord->recordHeader.recordType == TLS13_APPDATA_RECORD);
        assert(tls13_ntohs(recvdFinRecord->recordHeader.protoVersion) == TLS12_PROTO_VERSION || \
               tls13_ntohs(recvdFinRecord->recordHeader.protoVersion) == TLS13_PROTO_VERSION);
        assert(true == tls13_verify_authTag(recvdFinRecord->encryptedData, tempLen, 
                                            (recvdFinRecord->authTag + authTagOffset), TLS13_RECORD_AUTHTAG_LEN, cs));

        //tsl13_finishedRecordDataDecrypted_t *verf = (tsl13_finishedRecordDataDecrypted_t *)&recvdFinRecord->encryptedData;
        tsl13_finishedRecordDataDecrypted_t *verf = calloc(1, verfLen);
        {
            tls13_decrypt((uint8_t *)recvdFinRecord->encryptedData, (verfLen - TLS13_RECORD_HEADER_SIZE), (uint8_t *)verf, cs);
            //assert(verf->recordType == TLS13_HANDSHAKE_RECORD);
            assert(verf->finished.handshakeHdr.handshakeType == TLS13_HST_FINISHED);

            if(dVerify != NULL){
                //memcpy(dVerify, verf->finished.verifyData, verfLen - TLS13_RECORD_HEADER_SIZE);
                memcpy(dVerify, verf->finished.verifyData, verfLen - TLS13_RECORD_HEADER_SIZE);
                *dVerifyLen = verfLen - TLS13_RECORD_HEADER_SIZE;
            }
        }
        free(verf);
    }      
    free(tmp);
}

uint16_t tls13_prepareClientWrappedRecord(const uint8_t *dVerify, const uint16_t dVerifyLen, 
                                            const uint8_t *appData, const uint8_t appDataLen, tls13_cipherSuite_e cs, uint8_t *tlsPkt)
{
    uint32_t len = 0;
    uint16_t offset = 0;
    uint32_t tempLen = 0;
    tempLen = sizeof(tls13_clientWrappedRecord_t) + dVerifyLen + appDataLen;
    tls13_clientWrappedRecord_t *record = calloc(1, tempLen);

    /* Fill and serialize the change cipher spec structure */
    tls13_changeCipherSpec_t *cCCS = (tls13_changeCipherSpec_t *)&record->clientCCS;
    {
        cCCS->recordHeader.recordType   = TLS13_CHANGE_CIPHERSPEC_RECORD;
        cCCS->recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION); /* Legacy TLS 1.2 */
        cCCS->payload                   = 0x01;
        cCCS->recordHeader.recordLen    = tls13_ntohs(0x0001);
        len += sizeof(tls13_changeCipherSpec_t);
    }
    // If client also wands to respond to a certificate request, it should be able to send certificate and cert verify records
    tls13_finishedRecord_t *finishedRecord = (tls13_finishedRecord_t *)((uint8_t *)&record->finishedRecord);
    {
        finishedRecord->recordHeader.recordType   = TLS13_APPDATA_RECORD;
        finishedRecord->recordHeader.protoVersion = tls13_htons(TLS12_PROTO_VERSION); /* Legacy TLS 1.2 */
        
        tsl13_finishedRecordDataDecrypted_t *verif = calloc(1, 200);
        {
            verif->finished.handshakeHdr.handshakeType = TLS13_HST_FINISHED;
            verif->finished.handshakeHdr.handshakeMsgLen = tls13_htonss(dVerifyLen);
            /* Data to be encrypted before copying */
            memcpy(verif->finished.verifyData, dVerify, dVerifyLen);  // encrypted data length to be standardised. data encrypted with the server handshake key
        }
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
    tls13_appDataRecord_t *aDR = (tls13_appDataRecord_t *)((uint8_t *)&record->appDataRecord + offset);
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

void tls13_extractClientWrappedRecord(const uint8_t *tlsPkt, uint8_t *dVerify, uint16_t *dVerifyLen, uint8_t *appData, uint16_t *appDataLen, tls13_cipherSuite_e cs)
{
    uint16_t authTagOffset = 0;
    uint16_t ccspLen = ((uint16_t)tlsPkt[3] << 8 | tlsPkt[4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t verifLen = ((uint16_t)tlsPkt[ccspLen + 3] << 8 | tlsPkt[ccspLen + 4]) + TLS13_RECORD_HEADER_SIZE;
    uint16_t dataLen = ((uint16_t)tlsPkt[ccspLen + verifLen + 3] << 8 | tlsPkt[ccspLen + verifLen + 4]) + TLS13_RECORD_HEADER_SIZE;

    tls13_clientWrappedRecord_t *tmp = calloc(1, ccspLen + ccspLen + verifLen);

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

uint16_t tls13_prepareServerSessionTicketRecord(const uint8_t *sessionTkt, const uint8_t sessionTktLen, tls13_cipherSuite_e cs, uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_serverSesTktWrappedRecord_t *sNST = calloc(1, (sizeof(tls13_serverSesTktWrappedRecord_t) + 1200));

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

void tls13_extractSessionTicket(tls13_serverNewSesTkt_t *sessionTkt, tls13_cipherSuite_e cs, const uint8_t *tlsPkt)
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
uint16_t tls13_prepareAppData(const uint8_t *dIn, const uint16_t dInLen, tls13_cipherSuite_e cs, uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    uint16_t len = 0;
    tls13_appDataRecord_t *app = calloc(1, sizeof(tls13_appDataRecord_t));

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

void tls13_extractEncryptedAppData(uint8_t *dOut, uint16_t *dOutLen, tls13_cipherSuite_e cs, const uint8_t *tlsPkt)
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
    //memcpy(dOut, tmp->encryptedData, dataSize);
    tls13_decrypt(tmp->encryptedData, dataSize, dOut, cs);
    *dOutLen = dataSize;

    // memcpy(authTag, tmp->authTag, TLS13_RECORD_AUTHTAG_LEN);
    assert(true == tls13_verify_authTag(tmp->encryptedData, dataSize, (tmp->authTag + dataSize), TLS13_RECORD_AUTHTAG_LEN, cs));
    free(tmp);
}

uint16_t tls13_prepareAlertRecord(const tls13_alert_t *alertData, tls13_cipherSuite_e cs, uint8_t *tlsPkt)
{
    uint16_t len = 0;
    uint16_t offset = 0;
    tls13_wrappedAlertRecord_t *war = calloc(1, 100);
    tls13_alert_t alert;

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

void tls13_extractAlertRecord(tls13_alert_t *alertData, tls13_cipherSuite_e cs, const uint8_t *tlsPkt)
{
    uint16_t offset = 0;
    tls13_wrappedAlertRecord_t *war = calloc(1, 100);

    assert(war->recordHeader.recordType == TLS13_ALERT_RECORD);
    assert(war->recordHeader.protoVersion == TLS13_PROTO_VERSION || war->recordHeader.protoVersion == TLS12_PROTO_VERSION);
    assert(war->recordHeader.recordLen == (sizeof(tls13_alert_t) + TLS13_RECORD_AUTHTAG_LEN));
    //memcpy(alertData, &war->alert, sizeof(tls13_alert_t));
    tls13_decrypt((uint8_t *)&war->alert, sizeof(tls13_alert_t), (uint8_t *)alertData, cs);
    offset += sizeof(tls13_alert_t);
    tls13_verify_authTag((uint8_t *)&war->alert, sizeof(tls13_alert_t), (war->authTag + offset), TLS13_RECORD_AUTHTAG_LEN, cs);
    free(war);
}