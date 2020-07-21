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
#include <curl/curl.h>
#include <time.h>
#include <libetpan/libetpan.h>
#include <dirent.h>

#include "utils/base64.h"
#include "utils/socketUtils.h"
#include "cipherPOC.h"
#include "signaturePOC.h"
#include "utils/aesUtils.h"

binn* parseEmail(char* filename);

/**
 * @brief This is a checker to know if there is already params stored on the disk, so we don't have to regenerate it.
 * @param userID The user email that needs his params back.
 * @return 0 if no params stored, 1 if stored
 */
int checkIfParamsExistAlready(char *userID);

/**
 * @brief Get the Encrypted params in a file, asking the user for his password to decrypt it.
 * @param mpkSession The structure to store the mpk_e
 * @param mpkSignature The structure to store the mpk_s
 * @param encryption_secret The bn to store the secret_e
 * @param signature_secret The bn to store the secret_s
 * @param encryptionPk The structure to store the pk_e
 * @param signaturePk The structure to store the pk_s
 * @param userID The userID of the searched params
 */
void getParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
               bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID);

/**
 * @brief If no params are stored on the disk, we can generate them and send them to the KGC, the function does just that.
 * @param mpkSession The structure to store the mpk_e
 * @param mpkSignature The structure to store the mpk_s
 * @param encryption_secret The bn to store the secret_e
 * @param signature_secret The bn to store the secret_s
 * @param encryptionPk The structure to store the pk_e
 * @param signaturePk The structure to store the pk_s
 * @param userID The userID of the searched params
 */
void generateAndSendParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
                           bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID);


void generateAndSendPKs(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
                           bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID);
/**
 * When they are generated the params are saved on a file. This function ask the user for a password and encrypt his params.
 * @param mpkSession The mpke_e to store
 * @param mpkSignature The mpk_s to store
 * @param encryption_secret The secret_e to store
 * @param signature_secret The secret_s to store
 * @param encryptionPk The pk_e to store
 * @param signaturePk The pk_s to store
 * @param userID The userID of the stored params
 */

void getGlobalParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature);

binn* getSecretsValue(char *userID, char *userPassword, unsigned char **salt, unsigned char **nonce);

void getPk(encryption_pk *encryptionPk, signature_pk *signaturePk, char *userID);

void saveSecretsValue(binn *secrets, char *userID, char *userPassword, unsigned char **salt, unsigned char **nonce);

void getSecretKey(binn *secrets, char *timestamp, encryption_mpk mpkSession, signature_mpk mpkSignature, encryption_sk *encryptionSk, signature_sk *signatureSk, char *userID);

/**
 * @brief A small function to initiate a new connection to the KGC in order to ask something to it.
 * @return The socket to use
 */
int connectToKGC();

int sendmail(char* destination, char* source, char* subject, char* nonceAES, char* IDused, char* content, char* signature, char* cipher, char *email, char *password);
int checkmail(char *email, char *password);
#endif //POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
