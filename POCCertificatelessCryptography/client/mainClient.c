#include "cipherPOC.h"
#include "signaturePOC.h"
#include "utils/aesUtils.h"
#include "sodium.h"
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#define PORT 10005

int main() {
    if(core_init() == RLC_ERR){
        printf("RELIC INIT ERROR !\n");
    }
    if(sodium_init() < 0) {
        printf("LIBSODIUM INIT ERROR !\n");
    }
    if(pc_param_set_any() == RLC_OK){
        // Server doing this once
        pc_param_print();
        // Setup the encrypting and signing parameters for KGC

        printf("Security : %d\n", pc_param_level());

        int sock = 0;
        struct sockaddr_in serv_addr;

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        // Convert IPv4 and IPv6 addresses from text to binary form
        if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }

        // MPK struct, Master Public Key structure to store
        mpkStruct mpkSession;
        mpkStructSig mpkSignature;

        char* initMessage = "HELO:IDHere";
        // TODO malloc this and free it after received data
        char buffer[52000] = {0};
        send(sock , initMessage , strlen(initMessage) , 0 );
        printf("Hello message sent\n");
        read(sock, buffer, 52000);
        binn *list;
        list = binn_open(buffer);
        binn *mpks, *mpke;
        mpks = binn_list_object(list, 1);
        mpke = binn_list_object(list, 2);
        deserialize_MPKS(mpks, &mpkSignature);
        deserialize_MPKE(mpke, &mpkSession);
        //binn_free(mpke);
        //binn_free(mpks);
        binn_free(list);

        // Now we can go for user's private keys (encrypting and signing)
        bn_t x;
        setSec(&x);

        bn_t xSig;
        setSecSig(&xSig);
        // -------------------------------------------------------------
        // Private keys set

        // Now we can go to set Public keys for both signing and encrypting
        PK myPK;
        setPub(x, mpkSession, &myPK);

        PKSig myPKSig;
        setPubSig(xSig, mpkSignature, &myPKSig);

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }
        char bufferPK[1024] = {0};
        // TODO : construct our PK binn
        binn* listPK;
        listPK = binn_list();
        binn* PKE, *PKS;
        PKE = binn_object();
        PKS = binn_object();
        serialize_PKE(PKE, myPK);
        serialize_PKS(PKS, myPKSig);
        binn_list_add_object(listPK, PKE);
        binn_list_add_object(listPK, PKS);
        binn_free(PKE);
        binn_free(PKS);

        char *PKanounce = "PK:mickael.bonjour@hotmail.fr,";
        memcpy(bufferPK, PKanounce, strlen(PKanounce) + 1);
        memcpy(&bufferPK[strlen(PKanounce) + 1], binn_ptr(listPK), binn_size(listPK));

        send(sock, bufferPK, strlen(PKanounce) + binn_size(listPK), 0);
        binn_free(listPK);
        // -----------------------------------------------------------------
        // Public keys set


        // The other user takes ID of the destination and PK to encrypt his message
        // With the final version we will need to append a timestamp on the ID
        char ID[] = "mickael.bonjour@hotmail.fr";

        gt_t AESK;
        gt_null(AESK);
        gt_new(AESK);
        // For now we take m (AES Key) randomly from Gt
        gt_rand(AESK);

        unsigned char aesk [crypto_secretbox_KEYBYTES];
        get_key(aesk, AESK);

        char* m = "This message will be encrypted";
        printf("Message : %s\n", m);
        unsigned char nonceAES[crypto_aead_aes256gcm_NPUBBYTES];
        size_t m_len = strlen(m);
        unsigned long long cipher_len;
        unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
        encrypt_message(m, aesk, nonceAES, ciphertextAES, &cipher_len, &m_len);
        printf("Encrypted message : %s\n", ciphertextAES);

        cipher c;
        encrypt(AESK, myPK, ID, mpkSession, &c);

        // For the signature we need our PPK
        PPKSig myPartialKeysSig;
        // TODO : Verify if ok the deserialize
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }
        char bufferPPK[1024] = {0};
        char *signExtract = "SE:mickael.bonjour@hotmail.fr";
        send(sock, signExtract, strlen(signExtract), 0);
        read(sock, bufferPPK, 1024);
        deserialize_PPKS(bufferPPK, &myPartialKeysSig);

        // Computes Secret User Keys for Signature
        SKSig mySecretKeysSig;
        setPrivSig(xSig, myPartialKeysSig, mpkSignature, ID, &mySecretKeysSig);

        // Computes the message to sign, so the cipher struct
        int c0size = gt_size_bin(c.c0,1);
        int c1Size = g1_size_bin(c.c1, 1);
        int c2Size = g2_size_bin(c.c2, 1);
        int c3Size = g2_size_bin(c.c3, 1);
        uint8_t mSig[c0size+c1Size+c2Size+c3Size];
        gt_write_bin(mSig, c0size, c.c0, 1);
        g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
        g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
        g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);

        // Structure of an signature
        signature s;
        // We can sign using our private keys and public ones
        sign(mSig, mySecretKeysSig, myPKSig, ID, mpkSignature, &s);
        // ----------------------------------------------------------------------
        // Now the message is encrypted and authentified with an AES Key and the key is encrypted and signed using CLPKC
        // ----------------------------------------------------------------------


        // We can go for decrypting and verification
        // For this we need our Partial Private Keys with the ID used to encrypt the message

        // We can verify directly with the public keys of the sender
        int test = verify(s, myPKSig, mpkSignature, ID, mSig);
        printf("\nVerification of the key (0 if correct 1 if not) : %d\n", test);
        // if the verif is ok we can continue, otherwise we can stop here
        if(test == 0) {
            PPK myPartialKeys;
            // TODO : Verify if ok the deserialize
            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                printf("\n Socket creation error \n");
                return -1;
            }
            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
            {
                printf("\nConnection Failed \n");
                return -1;
            }
            char bufferPPKE[1024] = {0};
            char *encExtract = "EE:mickael.bonjour@hotmail.fr";
            send(sock, encExtract, strlen(encExtract), 0);
            read(sock, bufferPPKE, 1024);
            deserialize_PPKE(bufferPPKE, &myPartialKeys);

            // Computes Secret User Keys
            SK mySecretKeys;
            g2_null(mySecretKeys->s1)
            g2_new(mySecretKeys->s1)

            g1_null(mySecretKeys->s2)
            g1_new(mySecretKeys->s2)
            setPriv(x, myPartialKeys, mpkSession, ID, &mySecretKeys);

            // We can decrypt now
            gt_t decryptedMessage;
            gt_null(decryptedMessage)
            gt_new(decryptedMessage)
            decrypt(c, mySecretKeys, myPK, mpkSession, ID, &decryptedMessage);

            char aeskDecrypted[crypto_secretbox_KEYBYTES];
            get_key(aeskDecrypted, decryptedMessage);

            unsigned char decrypted[m_len];
            decrypt_message(decrypted, ciphertextAES, nonceAES, aeskDecrypted, cipher_len);
            printf("Decrypted message : %s\n", decrypted);
        }

        // For test purposes
        // We change the message to see the signature not being correct again
        unsigned char* mSigCorrupt = "The message to be signed !!";
        printf("Message changed to simulate corruption\n");

        // We can verify now with the public keys of the sender
        test = verify(s, myPKSig, mpkSignature, ID, mSigCorrupt);
        printf("Verification (0 if correct 1 if not) : %d\n", test);
    }
    core_clean();
}