#include "cipherPOC.h"
#include "signaturePOC.h"
#include "sodium.h"

// Utils function for encrypting / decrypting AES_GCM
char* encrypt_message(const char* m, unsigned char* key, unsigned char* nonce, unsigned char* cipher, unsigned long long* cipher_len, const size_t* m_len){
    randombytes_buf(nonce, sizeof nonce);
    crypto_aead_aes256gcm_encrypt(cipher, cipher_len, m, *m_len,NULL,0,NULL, nonce, key);
}

void decrypt_message(unsigned char* decrypted, unsigned char* cipher, unsigned char* nonce, unsigned char* key, unsigned long long cipher_len){
    unsigned long long decrypted_len;
    if (cipher_len < crypto_aead_aes256gcm_ABYTES ||
        crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                      NULL,
                                      cipher, cipher_len,
                                      NULL,
                                      0,
                                      nonce, key) != 0) {
        /* message forged! */
        printf("Message not correctly authenticated ! Aborting decryption...\n");
    }
}

void get_key(char *aesk, gt_t originalM) {
    int sizeAESK = gt_size_bin(originalM,1);
    char aeskBin [sizeAESK];
    gt_write_bin(aeskBin, sizeAESK, originalM, 1);
    md_map_sh256(aesk, aeskBin, sizeAESK);
    printf("AES Key : ");
    for(int i=0;i < 32;i++)
        printf("%02X",(unsigned char)aesk[i]);
    printf("\n");
}

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

        // MPK struct, Master Public Key structure to store
        mpkStruct mpkSession;
        mpkStructSig mpkSignature;

        // Master secret key of KGC for encrypting
        g2_t msk;
        g2_null(msk)
        g2_new(msk)

        setup(256, &mpkSession, &msk);

        // Master key of KGC for signing
        bn_t masterSecret;
        bn_null(masterSecret)
        bn_new(masterSecret)

        setupSig(256, &mpkSignature, &masterSecret);
        printf("Setup successful !\n");
        // -----------------------------------------------------------------
        // At this point, setup of KGC for encrypting and signing is successful

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

        //The sender needs to extract (via KGC) and setPriv to get his private key and sign the message
        extractSig(mpkSignature, masterSecret, ID , &myPartialKeysSig);

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
            g2_null(myPartialKeys->d1)
            g2_new(myPartialKeys->d1)

            g1_null(myPartialKeys->d2)
            g1_new(myPartialKeys->d2)

            //The receiver needs to extract (via KGC) and setPriv to get his private key and decrypt the cipher
            extract(mpkSession, msk, ID, &myPartialKeys);

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


