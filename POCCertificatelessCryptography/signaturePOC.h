/**
 * @file signaturePOC.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 14 mai 2020
 * @brief All the resources to sign/verify with a CL-PKC scheme using the RELIC library
 *        Signature scheme used : https://link.springer.com/content/pdf/10.1007/11767480_20.pdf
 */

#ifndef TEST_RELIC_SIGNATUREPOC_H
#define TEST_RELIC_SIGNATUREPOC_H
#include <stdio.h>
#include <relic.h>
#include <string.h>
#include <binn.h>

#define MESSAGE_SPACE 257

/**
 * @struct mpkStructSig
 * @brief mpkStructSig is a struct to handle the Master Public Key for the signature, it has 2 g1 elements : P, Ppub
 */
typedef struct mpkStructSig mpkStructSig;
struct mpkStructSig {
    g1_t P, Ppub;
};

/**
 * @struct PKSig
 * @brief This is a structure to handle the Public Keys of the user using signature across the application.
 *        Public keys are just a G1 element Ppub.
 */
typedef struct PKSig PKSig;
struct PKSig {
    g1_t Ppub;
};

/**
 * @struct SKSig
 * @brief This is a structure to store the Secret keys of an user using signatures across the application.
 *        Secret keys are composed with a G2 element D (actually this is the Partial Private Key form the KGC) and a value randomly choosen x.
 */
typedef struct SKSig SKSig;
struct SKSig {
    g2_t D;
    bn_t x;
};

/**
 * @struct PPKSig
 * @brief This is a structure to store the partial private key given by the KGC to the client.
 *        It's composed of a G2 element D.
 */
typedef struct PPKSig PPKSig;
struct PPKSig {
    g2_t D;
};

/**
 * @struct signature
 * @brief The structure that can handle the signature given when we sign something with my algorithm.
 *        It's composed of an G1 element and a G2 element.
 */
typedef struct Signature signature;
struct Signature {
    g1_t U;
    g2_t V;
};

/**
 * @brief Hash functions mapping data bytes to a point on the G2 curve. Hash domain Separation with H1 and H3
 * @param to_point The resulting point
 * @param bytes_from The data that needs to be mapped
 * @param len_bytes Size of the data to map
 */
void functionH2(g2_t* to_point, char* bytes_from, int len_bytes);
/**
 * @brief Hash functions mapping data bytes to a point on the G2 curve. Hash domain Separation with H1 and H2
 * @param to_point The resulting point
 * @param bytes_from The data that needs to be mapped
 * @param len_bytes Size of the data to map
 */
void functionH3(g2_t* to_point, char* bytes_from, int len_bytes);

/**
 * @brief Setup of the KGC for the signature opeations, this is necessary as I don't use the same scheme on encrypting/signing.
 * @param i Security level necessary
 * @param pStruct Structure handling the Master Public Key generated
 * @param ptr bn_t storing the master secret key of the KGC (generated at setup)
 */
void setupSig(int i, mpkStructSig *pStruct, bn_t *ptr);

/**
 * @brief Extraction of the Partial Private Key, used by the KGC to provide the user.
 * @param mpk Master Public Key of the KGC
 * @param msk Master secret Key of the KGC
 * @param ID The ID we need to extract for.
 * @param partialKeys The resulting Partial Private key for the given ID
 */
void extractSig(mpkStructSig mpk, bn_t msk, char* ID, PPKSig * partialKeys);

/**
 * @brief Generate a secret value for the user
 * @param x The value generated
 */
void setSecSig(bn_t* x);

/**
 * @brief Compute the Public Key of a user.
 * @param x The secret value of the user (Generated by SetSecSig)
 * @param mpkSession Master Publc Key of the KGC
 * @param PKtoGen The resulting Public Key for the user
 */
void setPubSig(bn_t x, mpkStructSig mpkSession, PKSig* PKtoGen);

/**
 * @brief Compute the secret key of an user given his secret value and the partial private key generated from the KGC.
 * @param x The secret value generated by SetSecSig
 * @param d The Partial Private Key given by the KGC by extract
 * @param mpk Master Public Key of the KGC
 * @param ID The ID used in the signature to verify correctly
 * @param secretKeys The Secret Key of the user generated
 */
void setPrivSig(bn_t x,PPKSig d, mpkStructSig mpk, char* ID, SKSig * secretKeys);

/**
 * @brief The sign operation of a message
 * @param m The message to sign
 * @param sk Secret Key of the signer
 * @param pk The Public Key of the signer
 * @param ID The ID of the user
 * @param mpk Master Publi Keys of the KGC
 * @param s Th resulting signature
 */
void sign(unsigned char* m, SKSig sk, PKSig pk, unsigned char* ID, mpkStructSig mpk, signature* s);

/**
 * @brief The verification of a given message.
 * @param s Signature of the message
 * @param pk Public Key of the Signer
 * @param mpk Master Public Key of the KGC
 * @param ID The ID the signer used to sign
 * @param m The message signed to verify
 * @return 0 if OK 1 if not
 */
int verify(signature s, PKSig pk, mpkStructSig mpk, char* ID, unsigned char* m);

/**
 * @brief Serialization of the mpkStructSig with the binn library
 * @param obj The resulting binn Object
 * @param mpks Master Public Key structure to serialize
 */
void serialize_MPKS(binn* obj, mpkStructSig mpks);

/**
 * @brief Deserialization of the mpkStructSig with the binn library
 * @param obj The binn object containing the mpkStruc
 * @param mpks The resulting Master Public Key structure
 */
void deserialize_MPKS(binn* obj, mpkStructSig* newMpk);
/**
 * @brief Serilization of Partial Private Key struct
 * @param obj THe binn object resulting
 * @param ppks The partial private key struct to serialize
 */
void serialize_PPKS(binn* obj, PPKSig ppks);

/**
 * @brief Deserialization of a binn object containing partial private key.
 * @param buffer The buffer of binn object
 * @param newPpk The resulting Partial Private Key struct
 */
void deserialize_PPKS(void* buffer, PPKSig* newPpk);

/**
 * @brief Serialization of the Public Key structure
 * @param obj The binn object resulting
 * @param pks The Public Key to serialize
 */
void serialize_PKS(binn* obj, PKSig pks);
/**
 * @brief Deserialization of a binn object containing public key.
 * @param buffer The buffer of binn object
 * @param newPk The resulting Public Key struct
 */
void deserialize_PKS(void* buffer, PKSig* newPk);

#endif //TEST_RELIC_SIGNATUREPOC_H
