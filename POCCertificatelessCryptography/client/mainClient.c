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

#define PORT 10008

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
        //char buffer[52000] = {0};
        send(sock , initMessage , strlen(initMessage) , 0 );
        printf("Hello message sent\n");

        unsigned char buf[52000];  //10Kb fixed-size buffer
        size_t sizeReceived = recvAll(sock, buf);
        binn *list;
        list = binn_open(buf);
        binn *mpks, *mpke;
        mpks = binn_list_object(list, 1);
        mpke = binn_list_object(list, 2);
        deserialize_MPKS(mpks, &mpkSignature);
        deserialize_MPKE(mpke, &mpkSession);
        //binn_free(mpke);
        //binn_free(mpks);
        binn_free(list);

        // Now we can go for user's private keys (encrypting and signing)
        bn_t xAlice;
        setSec(&xAlice);

        bn_t xSigAlice;
        setSecSig(&xSigAlice);
        // -------------------------------------------------------------
        // Private keys set for Alice

        // Now we can go to set Public keys for both signing and encrypting
        PK PKAlice;
        setPub(xAlice, mpkSession, &PKAlice);

        PKSig PKSigAlice;
        setPubSig(xSigAlice, mpkSignature, &PKSigAlice);
        // --------------------------------------------------------------
        // Alice done

        // Now we can go for user's private keys (encrypting and signing)
        bn_t xBob;
        setSec(&xBob);

        bn_t xSigBob;
        setSecSig(&xSigBob);
        // -------------------------------------------------------------
        // Private keys set for Bob

        // Now we can go to set Public keys for both signing and encrypting
        PK PKBob;
        setPub(xBob, mpkSession, &PKBob);

        PKSig PKSigBob;
        setPubSig(xSigBob, mpkSignature, &PKSigBob);

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }

        char bufferPKAlice[1024] = {0};
        // TODO : construct our PK binn
        binn* listPKAlice;
        listPKAlice = binn_list();
        binn* PKE, *PKS;
        PKE = binn_object();
        PKS = binn_object();
        serialize_PKE(PKE, PKAlice);
        serialize_PKS(PKS, PKSigAlice);
        binn_list_add_object(listPKAlice, PKE);
        binn_list_add_object(listPKAlice, PKS);
        binn_free(PKE);
        binn_free(PKS);

        char *PKanounceAlice = "PK:alice@mail.ch,";
        memcpy(bufferPKAlice, PKanounceAlice, strlen(PKanounceAlice));
        size_t outLen;
        unsigned char* b64 = base64_encode(binn_ptr(listPKAlice), binn_size(listPKAlice), &outLen);
        printf("%s\n", b64);
        memcpy(&bufferPKAlice[strlen(PKanounceAlice)], b64, outLen);

        int sizeSent = send(sock, bufferPKAlice, strlen(PKanounceAlice) + outLen, 0);
        printf("Size of PK : %d\n", sizeSent);
        binn_free(listPKAlice);
        // -----------------------------------------------------------------
        // Public keys set

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
            return -1;
        }
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }
        char bufferPKBob[1024] = {0};
        // TODO : construct our PK binn
        binn* listPKBob;
        listPKBob = binn_list();
        binn* PKEBob, *PKSBob;
        PKEBob = binn_object();
        PKSBob = binn_object();
        serialize_PKE(PKEBob, PKBob);
        serialize_PKS(PKSBob, PKSigBob);
        binn_list_add_object(listPKBob, PKEBob);
        binn_list_add_object(listPKBob, PKSBob);
        binn_free(PKEBob);
        binn_free(PKSBob);
        char *PKanounceBob = "PK:bob@mail.ch,";
        memcpy(bufferPKBob, PKanounceBob, strlen(PKanounceBob));
        //memcpy(&bufferPKBob[strlen(PKanounceBob) + 1], binn_ptr(listPKBob), binn_size(listPKBob));
        size_t outLenBob;
        unsigned char* b64Bob = base64_encode(binn_ptr(listPKBob), binn_size(listPKBob), &outLenBob);
        printf("%s\n", b64Bob);
        memcpy(&bufferPKBob[strlen(PKanounceBob)], b64Bob, outLenBob);

        send(sock, bufferPKBob, strlen(PKanounceBob) + outLenBob, 0);
        binn_free(listPKBob);
        // -----------------------------------------------------------------
        // Public keys set



        // Test recuperation PKs
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\n Socket creation error \n");
        }
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
        }
        char* testGPE = "GPE:bob@mail.ch";
        send(sock, testGPE, strlen(testGPE), 0);
        char bufferGPE[512] = {0};

        int testSize = recv(sock, bufferGPE, 512, 0);
        printf("%s\n", bufferGPE);
        PK PKBob2;
        size_t out_len_test;
        unsigned char * decodedTest = base64_decode(bufferGPE, testSize, &out_len_test);
        deserialize_PKE(decodedTest, &PKBob2);



        // The other user takes ID of the destination and PK to encrypt his message
        // With the final version we will need to append a timestamp on the ID
        char IDAlice[] = "alice@mail.ch";
        char IDBob[] = "bob@mail.ch";

        gt_t AESK;
        gt_null(AESK);
        gt_new(AESK);
        // For now we take m (AES Key) randomly from Gt
        gt_rand(AESK);

        unsigned char aesk [crypto_secretbox_KEYBYTES];
        get_key(aesk, AESK);

        char* m = "This message for Bob will be encrypted";
        printf("Message : %s\n", m);
        unsigned char nonceAES[crypto_aead_aes256gcm_NPUBBYTES];
        size_t m_len = strlen(m);
        unsigned long long cipher_len;
        unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
        encrypt_message(m, aesk, nonceAES, ciphertextAES, &cipher_len, &m_len);
        printf("Encrypted message : %s\n", ciphertextAES);

        cipher c;
        encrypt(AESK, PKBob, IDBob, mpkSession, &c);

        // For the signature we need our PPK
        PPKSig PartialKeysSigAlice;
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
        char *signExtract = "SE:alice@mail.ch";
        send(sock, signExtract, strlen(signExtract), 0);
        read(sock, bufferPPK, 1024);
        deserialize_PPKS(bufferPPK, &PartialKeysSigAlice);

        // Computes Secret User Keys for Signature
        SKSig SecretKeysSigAlice;
        setPrivSig(xSigAlice, PartialKeysSigAlice, mpkSignature, IDAlice, &SecretKeysSigAlice);

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
        sign(mSig, SecretKeysSigAlice, PKSigAlice, IDAlice, mpkSignature, &s);
        // ----------------------------------------------------------------------
        // Now the message is encrypted and authentified with an AES Key and the key is encrypted and signed using CLPKC
        // ----------------------------------------------------------------------

        // We can go for decrypting and verification
        // We can verify directly with the public keys of the sender
        int test = verify(s, PKSigAlice, mpkSignature, IDAlice, mSig);
        printf("\nVerification of the key (0 if correct 1 if not) : %d\n", test);
        // if the verif is ok we can continue, otherwise we can stop here
        if(test == 0) {
            // For this we need our Partial Private Keys with the ID used to encrypt the message
            PPK PartialKeysBob;
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
            char *encExtract = "EE:bob@mail.ch";
            send(sock, encExtract, strlen(encExtract), 0);
            read(sock, bufferPPKE, 1024);
            deserialize_PPKE(bufferPPKE, &PartialKeysBob);

            // Computes Secret User Keys
            SK SecretKeysBob;
            g2_null(SecretKeysBob->s1)
            g2_new(SecretKeysBob->s1)

            g1_null(SecretKeysBob->s2)
            g1_new(SecretKeysBob->s2)
            setPriv(xBob, PartialKeysBob, mpkSession, IDBob, &SecretKeysBob);

            // We can decrypt now
            gt_t decryptedMessage;
            gt_null(decryptedMessage)
            gt_new(decryptedMessage)
            decrypt(c, SecretKeysBob, PKBob, mpkSession, IDBob, &decryptedMessage);

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
        test = verify(s, PKSigAlice, mpkSignature, IDAlice, mSigCorrupt);
        printf("Verification (0 if correct 1 if not) : %d\n", test);
    }
    core_clean();
}