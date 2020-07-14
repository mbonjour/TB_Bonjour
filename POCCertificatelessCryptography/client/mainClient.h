//
// Created by mbonjour on 14.07.20.
//

#ifndef POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
#define POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
#include <sodium.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "utils/base64.h"
#include "utils/socketUtils.h"
#include "cipherPOC.h"
#include "signaturePOC.h"
#include "utils/aesUtils.h"

int checkIfParamsExistAlready();
void getParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
               bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID);
void generateAndSendParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
                           bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID);
void saveParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
                bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID);
int connectToKGC();
#endif //POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
