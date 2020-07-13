/**
 * @file cipherPOC.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 14 mai 2020
 * @brief All the resources to encrypt/decrypt with a CL-PKC scheme using the RELIC library
 *        Encryption Scheme used : https://eprint.iacr.org/2007/121.pdf
 */

#ifndef TEST_RELIC_CIPHERPOC_H
#define TEST_RELIC_CIPHERPOC_H
#include <stdio.h>
#include <relic.h>
#include <string.h>
#include <binn.h>

#define MESSAGE_SPACE 257

/**
 * @struct mpkStruct
 * @brief The structure containing the Master Public Key for encryption/decryption
 *        g, g1 G1 element
 *        g2 G2 element
 *        u, v Array of G2 eleemnts
 */
typedef struct mpkStruct mpkStruct;
struct mpkStruct {
    g1_t g, g1;
    g2_t g2;
    g2_t u[MESSAGE_SPACE];
    g2_t v[MESSAGE_SPACE];
};

/**
 * @struct PK
 * @brief Structure containing a publick key
 *        X G2 element
 *        Y G1 element
 */
typedef struct PK PK;
struct PK {
    g2_t X;
    g1_t Y;
};

/**
 * @struct SK
 * @brief Structure containing the Secret Key of an user
 *        s1 G2 element
 *        s2 G1 element
 */
typedef struct SK SK;
struct SK {
    g1_t s2;
    g2_t s1;
};

/**
 * @struct PPK
 * @brief Structure containing Partial Private Key information
 *        d1 G2 element
 *        d2 G1 element
 */
typedef struct PPK PPK;
struct PPK {
    g1_t d2;
    g2_t d1;
};

/**
 * @struct cipher
 * @brief Structure containing all the parts of a cipher
 */
typedef struct Cipher cipher;
struct Cipher {
    gt_t c0;
    g1_t c1;
    g2_t c2, c3;
};

/**
 * @brief Setup of the KGC for the encryption Scheme, generate master Public Key and master secret key
 * @param i Security level
 * @param pStruct The Master public key generated from the setup
 * @param ptr The Master secret key generated from the setup
 */
void setup(int i, mpkStruct *pStruct, g2_t *ptr);

/**
 * @brief Hash function to sum up some G2 points (used in the u,v mpk context)
 * @param var The data bytes to hash
 * @param suite The suite to use, need to be a G2 element array
 * @param result The resulting point on G2
 */
void F(const char *var, g2_t* suite, g2_t *result);

/**
 * @brief Extraction of the partial private key for a given ID
 * @param mpk tThe master public key of the KGC
 * @param msk The master secret key of the KGC
 * @param ID The ID given to extract the PPK for
 * @param partialKeys The resulting Partial Private Key struct
 */
void extract(mpkStruct mpk, g2_t msk, char* ID, PPK* partialKeys);

/**
 * @brief Set secret value randomly from Zp
 * @param x The random value randomly choosed
 */
void setSec(bn_t* x);

/**
 * @brief Set public key for a given secret value
 * @param x The secret value
 * @param mpkSession The Master Public Key of the KGC
 * @param PKtoGen The resulting Public key generated
 */
void setPub(bn_t x, mpkStruct mpkSession, PK* PKtoGen);

/**
 * @brief Setting Private key for a given ID
 * @param x The secret value of the user
 * @param d The Partial Private Key given by the KGC
 * @param mpk The Master Public Key of the KGC
 * @param ID The ID used on the ecryption typically
 * @param secretKeys The generated Secret Key
 */
void setPriv(bn_t x,PPK d, mpkStruct mpk, char* ID, SK* secretKeys);

/**
 * @brief Encryption of a GT element for a given ID and Public Key
 * @param m The Gt element to encrypt
 * @param pk The Public Key of the recipient
 * @param ID The ID of the receiver
 * @param mpk The master public key of the KGC
 * @param c The cipher generated from the encryption of m
 */
void encrypt(gt_t m, PK pk, unsigned char* ID, mpkStruct mpk, cipher* c);

/**
 * @brief Decryption of a given cipher struct
 * @param c The cipher to decrypt
 * @param sk The secret key of the recipient
 * @param pk The public key of the recipient
 * @param mpk The master public key of the KG
 * @param ID The ID of the recipient
 * @param m The Gt element resulting the decryption (the original message)
 */
void decrypt(cipher c, SK sk, PK pk, mpkStruct  mpk, char* ID, gt_t* m);

/**
 * @brief Serialize Master public key (encryption)
 * @param obj Binn object generated
 * @param mpke Master public key to serialize
 */
void serialize_MPKE(binn* obj, mpkStruct mpke);

/**
 * @brief Deserialize Master Public Key
 * @param obj Binn object to deserialize
 * @param newMpk MPK struct generated
 */
void deserialize_MPKE(binn* obj, mpkStruct* newMpk);

/**
 * @brief Serialize Partial Private Key (encryption)
 * @param obj Binn object generated
 * @param ppke Partial private key to serialize
 */
void serialize_PPKE(binn* obj, PPK ppke);
/**
 * @brief Deserialize Partial Private Key
 * @param obj Binn object to deserialize
 * @param newPpk PPK struct generated
 */
void deserialize_PPKE(void* buffer, PPK* newPpk);
/**
 * @brief Serialize Public Key (encryption)
 * @param obj Binn object generated
 * @param pk Public key to serialize
 */
void serialize_PKE(binn* obj, PK pk);
/**
 * @brief Deserialize Public Key
 * @param obj Binn object to deserialize
 * @param newPk PK struct generated
 */
void deserialize_PKE(void* buffer, PK* newPk);

#endif //TEST_RELIC_CIPHERPOC_H
