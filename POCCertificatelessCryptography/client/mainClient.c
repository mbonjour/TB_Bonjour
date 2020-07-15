#include "mainClient.h"

#define PORT 10002

int checkIfParamsExistAlready(char* userID){
    FILE *file;
    file = fopen(userID, "r");
    if (file){
        fclose(file);
        return 1;
    }
    return 0;
}

void getParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
               bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID){
    FILE *savedParams;
    binn *paramsObjBinn;
    savedParams = fopen(userID, "rb");
    unsigned char *decodedParams;
    if(savedParams) {
        fseek(savedParams, 0, SEEK_END);
        long fileSize = ftell(savedParams);
        fseek(savedParams, 0, SEEK_SET);

        char *paramsB64 = malloc(fileSize);
        fread(paramsB64, fileSize, 1, savedParams);
        fclose(savedParams);

        size_t outLen;
        decodedParams = base64_decode(paramsB64, fileSize, &outLen);
        paramsObjBinn = binn_open(decodedParams);

        free(paramsB64);
    } else {
        printf("Failed to open a file to save params\n");
        return;
    }

    binn *obj;
    obj = binn_list_object(paramsObjBinn, 1);
    deserialize_MPKE(obj, mpkSession);

    obj = binn_list_object(paramsObjBinn, 2);
    deserialize_MPKS(obj, mpkSignature);

    int size = 0;
    void *bnBin = NULL;
    bnBin = binn_list_blob(paramsObjBinn,3, &size);
    bn_read_bin(*encryption_secret, bnBin, size);

    bnBin = binn_list_blob(paramsObjBinn,4, &size);
    bn_read_bin(*signature_secret, bnBin, size);

    obj = binn_list_object(paramsObjBinn, 5);
    deserialize_PKE(obj, encryptionPk);

    obj = binn_list_object(paramsObjBinn, 6);
    deserialize_PKS(obj, signaturePk);

    char* userSaved = binn_list_str(paramsObjBinn, 7);
    strcpy(userID, userSaved);
    binn_free(paramsObjBinn);
    free(decodedParams);
}

void saveParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
                bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID){
    binn* list;
    list = binn_list();
    binn *obj;
    obj = binn_object();
    serialize_MPKE(obj, *mpkSession);
    binn_list_add_object(list, obj);
    binn_free(obj);

    obj = binn_object();
    serialize_MPKS(obj, *mpkSignature);
    binn_list_add_object(list, obj);
    binn_free(obj);

    obj = binn_object();
    int size = bn_size_bin(*encryption_secret);
    uint8_t *bin = malloc(size);
    bn_write_bin(bin, size, *encryption_secret);
    binn_list_add_blob(list, bin, size);
    binn_free(obj);
    free(bin);

    obj = binn_object();
    size = bn_size_bin(*signature_secret);
    bin = malloc(size);
    bn_write_bin(bin, size, *signature_secret);
    binn_list_add_blob(list, bin, size);
    binn_free(obj);
    free(bin);

    obj = binn_object();
    serialize_PKE(obj, *encryptionPk);
    binn_list_add_object(list, obj);
    binn_free(obj);

    // TODO : Verify if OK
    obj = binn_object();
    serialize_PKS(obj, *signaturePk);
    binn_list_add_object(list, obj);
    binn_free(obj);

    binn_list_add_str(list, userID);

    FILE *savingParams;
    savingParams = fopen(userID, "wb");
    if(savingParams){
        size_t outLen;
        unsigned char *b64params = base64_encode(binn_ptr(list), binn_size(list), &outLen);
        unsigned long strlenTest = strlen((char*) b64params);
        size_t test = fwrite(b64params, strlenTest, 1, savingParams);
        if(test > 0){
            printf("Params saved\n");
        } else {
            printf("Failed to save Params\n");
        }
        free(b64params);
        fclose(savingParams);
    } else {
        printf("Failed to open a file to save params\n");
    }
    binn_free(list);
}

void generateAndSendParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature, bn_t *encryption_secret,
        bn_t *signature_secret, encryption_pk *encryptionPk, signature_pk *signaturePk, char* userID){

    int sock = connectToKGC();

    binn *objToSend;
    objToSend = binn_object();
    binn_object_set_str(objToSend, "opCode", "HELO");
    binn_object_set_str(objToSend, "ID", userID);
    send(sock , binn_ptr(objToSend) , binn_size(objToSend) , 0 );
    binn_free(objToSend);
    printf("Retrieving all public params from KGC\n");

    unsigned char buf[52000];  //52Kb fixed-size buffer
    recvAll(sock, buf, 52000);

    binn *list;
    list = binn_open(buf);
    binn *mpks, *mpke;
    mpks = binn_list_object(list, 1);
    mpke = binn_list_object(list, 2);
    deserialize_MPKS(mpks, mpkSignature);
    deserialize_MPKE(mpke, mpkSession);
    binn_free(list);

    printf("Generating and saving secret values and public keys\n");
    // Now we can go for user's private keys (encrypting and signing)

    setSec(encryption_secret);
    setSecSig(signature_secret);
    // -------------------------------------------------------------
    // Private keys set for Alice

    // Now we can go to set Public keys for both signing and encrypting

    setPub(*encryption_secret, *mpkSession, encryptionPk);
    setPubSig(*signature_secret, *mpkSignature, signaturePk);

    sock = connectToKGC();

    binn* pkBinnObj;
    pkBinnObj = binn_list();
    binn* encryption_PkBinnObj, *signature_PkBinnObj;
    encryption_PkBinnObj = binn_object();
    signature_PkBinnObj = binn_object();
    serialize_PKE(encryption_PkBinnObj, *encryptionPk);
    serialize_PKS(signature_PkBinnObj, *signaturePk);
    binn_list_add_object(pkBinnObj, encryption_PkBinnObj);
    binn_list_add_object(pkBinnObj, signature_PkBinnObj);
    binn_free(encryption_PkBinnObj);
    binn_free(signature_PkBinnObj);

    binn* packetSendingPK;
    packetSendingPK = binn_object();
    binn_object_set_str(packetSendingPK, "opCode", "PK");
    binn_object_set_str(packetSendingPK, "ID", userID);

    size_t outLen;
    unsigned char* b64Payload = base64_encode(binn_ptr(pkBinnObj), binn_size(pkBinnObj), &outLen);
    printf("PK obj : %s\n", b64Payload);
    binn_object_set_str(packetSendingPK, "PK", b64Payload);
    // TODO : Vérifi si ok
    free(b64Payload);

    int sizeSent = send(sock, binn_ptr(packetSendingPK), binn_size(packetSendingPK), 0);
    printf("Size of PK : %d\n", sizeSent);
    binn_free(pkBinnObj);
    binn_free(packetSendingPK);
}


int connectToKGC(){
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
    return sock;
}


int main() {
    if(core_init() == RLC_ERR){
        printf("RELIC INIT ERROR !\n");
    }
    if(sodium_init() < 0) {
        printf("LIBSODIUM INIT ERROR !\n");
    }
    if(pc_param_set_any() == RLC_OK){
        pc_param_print();
        printf("Security : %d\n", pc_param_level());

        // MPK struct, Master Public Key structure to store
        encryption_mpk mpkSession;
        signature_mpk mpkSignature;
        bn_t encryption_secret;
        bn_null(encryption_secret)
        bn_new(encryption_secret)
        bn_t signature_secret;
        bn_null(signature_secret)
        bn_new(signature_secret)
        encryption_pk encryptionPk;
        signature_pk signaturePk;

        // Max size of an email address
        char* userID = malloc(320);
        printf("What's your email ?\n");
        fgets(userID, 320, stdin);
        userID[strlen(userID)-1] = '\x00';

        int existingParams = checkIfParamsExistAlready(userID);
        if(existingParams == 1){
            //TODO Recup params
            printf("Params found on disk, retrieving these\n");
            getParams(&mpkSession, &mpkSignature, &encryption_secret,
                      &signature_secret, &encryptionPk, &signaturePk, userID);
        }
        // If there are no params saved we can go for a full generation
        else {
            generateAndSendParams(&mpkSession, &mpkSignature, &encryption_secret, &signature_secret, &encryptionPk, &signaturePk, userID);
            saveParams(&mpkSession, &mpkSignature, &encryption_secret, &signature_secret, &encryptionPk, &signaturePk, userID);
        }
        printf("Do you want to send an email (0) or decrypt one (1) ?\n");
        int sendOrDecryptUser;
        char* charUserChoice = malloc(4);
        fgets(charUserChoice, 4, stdin);
        charUserChoice[strlen(charUserChoice)-1] = '\x00';

        sendOrDecryptUser = strtol(charUserChoice, NULL, 10);
        // If we want to send an email
        if(sendOrDecryptUser == 0) {
            // At this point we're sure that params are full, by generating them or retrieving from the user disk
            // So now we can ask the user about the email he want to send
            printf("Now params are loaded, please enter the destination address of the email :\n");
            char *destinationID = malloc(320);
            fgets(destinationID, 320, stdin);
            destinationID[strlen(destinationID)-1] = '\x00';

            // Max size seems to be like more than 130 chars but some email clients truncate to 130
            printf("What's the subject :\n");
            char *subject = malloc(130);
            fgets(subject, 130, stdin);
            subject[strlen(subject)-1] = '\x00';

            printf("Message :\n");
            //arbitrary size
            char *message = malloc(10000);
            fgets(message, 10000, stdin);
            message[strlen(message)-1] = '\x00';
            printf("\n\nHere is a summary of the mail that will be sent, are you ok (yes/no) ?\n");
            printf("From : %s\n", userID);
            printf("To : %s\n", destinationID);
            printf("Subject : %s\n", subject);
            printf("Content : %s\n", message);

            char *userChoice = malloc(4);
            fgets(userChoice, 4, stdin);
            userChoice[strlen(userChoice)-1] = '\x00';
            if (strcmp(userChoice, "no") == 0) {
                printf("Not implemented yet");
                return -1;
            }
            free(userChoice);

            //TODO : do this for all destination, or implement something on te KGC to send all the asked public keys
            int sock = connectToKGC();
            binn *getPKBinnObj;
            getPKBinnObj = binn_object();
            binn_object_set_str(getPKBinnObj, "opCode", "GPE");
            binn_object_set_str(getPKBinnObj, "ID", destinationID);
            send(sock, binn_ptr(getPKBinnObj), binn_size(getPKBinnObj), 0);
            binn_free(getPKBinnObj);

            char bufferGPE[512] = {0};
            int testSize = recv(sock, bufferGPE, 512, 0);
            // printf("%s\n", bufferGPE);
            encryption_pk encryption_destinationPk;
            size_t out_len_test;
            unsigned char *decodedTest = base64_decode(bufferGPE, testSize, &out_len_test);
            deserialize_PKE(decodedTest, &encryption_destinationPk);
            free(decodedTest);

            // The other user takes ID of the destination and PK to encrypt his message
            // With the final version we will need to append a timestamp on the ID

            gt_t AESK;gt_null(AESK);gt_new(AESK);
            // For now we take m (AES Key) randomly from Gt
            gt_rand(AESK);

            unsigned char aesk[crypto_secretbox_KEYBYTES];
            get_key(aesk, AESK);

            unsigned char nonceAES[crypto_aead_aes256gcm_NPUBBYTES];
            size_t m_len = strlen(message);
            unsigned long long cipher_len;
            unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
            encrypt_message(message, aesk, nonceAES, ciphertextAES, &cipher_len, &m_len);
            unsigned char *ciphertextB64 = base64_encode(ciphertextAES, cipher_len, NULL);
            printf("Encrypted message : %s\n", ciphertextB64);
            free(ciphertextB64);
            unsigned char *nonceAesB64 = base64_encode(nonceAES, crypto_aead_aes256gcm_NPUBBYTES, NULL);
            printf("Nonce message : %s\n", nonceAesB64);
            free(nonceAesB64);

            // Encryption of the AES Key with the Public key of the destination
            cipher c;
            encrypt(AESK, encryption_destinationPk, destinationID, mpkSession, &c);
            // TODO print base64 of cipher for decrypt
            binn *cipherBinnObect;
            cipherBinnObect = binn_object();
            serialize_Cipher(cipherBinnObect, c);
            unsigned char *cipherB64 = base64_encode(binn_ptr(cipherBinnObect), binn_size(cipherBinnObect), NULL);
            printf("Cipher base64 : %s\n", cipherB64);
            free(cipherB64);
            binn_free(cipherBinnObect);

            // For the signature we need our PPK
            signature_ppk signature_senderPpk;
            sock = connectToKGC();
            char bufferPPK[1024] = {0};
            binn *signatureExtractionSenderBinnObj;
            signatureExtractionSenderBinnObj = binn_object();
            binn_object_set_str(signatureExtractionSenderBinnObj, "opCode", "SE");
            binn_object_set_str(signatureExtractionSenderBinnObj, "ID", userID);
            send(sock, binn_ptr(signatureExtractionSenderBinnObj), binn_size(signatureExtractionSenderBinnObj), 0);
            binn_free(signatureExtractionSenderBinnObj);

            read(sock, bufferPPK, 1024);
            deserialize_PPKS(bufferPPK, &signature_senderPpk);

            // Computes Secret User Keys for Signature
            signature_sk signature_senderSk;
            setPrivSig(signature_secret, signature_senderPpk, mpkSignature, userID, &signature_senderSk);

            // Computes the message to sign, so the cipher struct
            int c0size = gt_size_bin(c.c0, 1);
            int c1Size = g1_size_bin(c.c1, 1);
            int c2Size = g2_size_bin(c.c2, 1);
            int c3Size = g2_size_bin(c.c3, 1);
            uint8_t mSig[c0size + c1Size + c2Size + c3Size];
            gt_write_bin(mSig, c0size, c.c0, 1);
            g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
            g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
            g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);

            // Structure of an signature
            signature s;
            // We can sign using our private keys and public ones
            sign(mSig, signature_senderSk, signaturePk, userID, mpkSignature, &s);
            // TODO print base64 of signature for decrypt
            binn *signatureObjBinn;
            signatureObjBinn = binn_object();
            serialize_Signature(signatureObjBinn, s);
            unsigned char *b64signatureObjBinn = base64_encode(binn_ptr(signatureObjBinn), binn_size(signatureObjBinn), NULL);
            printf("Signature (base64) : %s\n", b64signatureObjBinn);
            free(b64signatureObjBinn);
            binn_free(signatureObjBinn);

            //TODO : Construct a structure of the email to be able to send easily

            // ----------------------------------------------------------------------
            // Now the message is encrypted and authentified with an AES Key and the key is encrypted and signed using CLPKC
            // ----------------------------------------------------------------------
            free(message);
            free(subject);
            free(destinationID);
        }
        /*
         *  AES Key : F1821D8CFF0B1BBDD9B083F32DE75B4A7340F75E36C28FE4E3AEEE8E5CB1E865
Encrypted message : cVfiJ6cx9P4JEMKYkRPwGyea8YM=

Nonce message : AUt1ViLpgnN3JoD2

Cipher base64 : 4oAAApAEAkMwwIAAAYAFhbmlejjqWrrQnJRZ0O3ttk3vfm3Qig/uhHi2gRzZvp/GPd49E/KTyQZ6GLwW73oZyRZr9dsnPAjWwnlnBUkQf0Xi3WWfZ80QFGrYrSqpiU90hz70Vog0Dye+bkFLAqUHHryDREitMz5XQjDw/8BesUxkU/olCkfUgWjXddXBJm+AeZ3tUIK2Be3ZG5dpkycLF1So6L2OjntjD+Z64gwvrmHHvBdhDW6QsWtLiJlI1VKRnBZ2ikrKrUoGP8L2evcEVLF8Q9vmG5v1hlRkaAItF0E+ej6Eom9YUZQsRgzyl5aN0sgm9o3bNuyEJKtvohcLqprKO6ii2qqgXE6Nc5gRvZaCASp5nJz7tt8guXi2pA1p1znnofOLdAv1G62/y+sRo2/Y1Kd1exQnDSjTOFjV4wJx8lA0KmzV2prafoeSCIe6kcOGWduFfFzxUQAO+bcLSBZhi6kaBx1v5gO8IostwAUbJ1s8LDx3zBCWpqL3FLQknyGyX6VWf57hiyxK3YMCQzHAMQINAF58CmO7ZNcnM6VBxhvhv1eIrox12JJtFgGe3dzeASYrilkJqNMYn+Q7sIODJQgCQzLAYQMGaOruZsK806verM8wEg3n0CH/1YzcIyvQGqlYHICVEHlPr04+HDQjR9tCFxUlZw4Zf1OIGFK3mCnn6y0gteAJf8p2B8vAN+4rsMDro/c8Z2O3te/icyT7BCSvyO/z+wICQzPAYQIRul2bfFT4Fu0ab5nNU5hS8oICIC6nfFx6U+bilO7mPg/fx9ZVMe+W746pr8ICPckEn0guYWSHqUVNvNmc4lZ356Ubzv49DAfF8XGjnp4FhGutUJl3KBJ9A4mocc/Y9Ws=

Signature (base64) : 4oAAAKACAVXAMQMNHbEYCfNUF7t3ljZf5w/za2c4flQJVWtjrV0iAck/aAt3R+A8w8TyipYR65Gc5PABVsBhAhTeoju/hssBuuWc4pte/XKm0TkeTBV4WuFXK9ols08dMnK4eMg/1HRXdcTZjTJl4hieO0G1FTuNslax21Oexovi6+4SKlyugiEYFQO+JNwj5t0EcOD5gxb2FLldBzzo9g==
         */
        // If we want to decrypt an email
        else {
            // TODO : Remove and replace by getting the email
            printf("From ?\n");
            char *sourceAddress = malloc(320);
            fgets(sourceAddress, 320, stdin);
            sourceAddress[strlen(sourceAddress)-1] = '\x00';

            printf("Base64 of signature ?\n");
            char *b64Signature = malloc(300);
            fgets(b64Signature, 300, stdin);
            b64Signature[strlen(b64Signature)-1] = '\x00';

            printf("Base64 of cipher ?\n");
            char *b64Cipher = malloc(1000);
            fgets(b64Cipher, 1000, stdin);
            b64Cipher[strlen(b64Cipher)-1] = '\x00';

            printf("Base64 of encrypted mesage ?\n");
            char *b64Encrypted = malloc(300);
            fgets(b64Encrypted, 300, stdin);
            b64Encrypted[strlen(b64Encrypted)-1] = '\x00';

            printf("Base64 of nonce ?\n");
            char *b64Nonce = malloc(100);
            fgets(b64Nonce, 100, stdin);
            b64Nonce[strlen(b64Nonce)-1] = '\x00';

            signature s;
            size_t outLen;
            unsigned char *signatureBinn = base64_decode(b64Signature, strlen(b64Signature), &outLen);
            deserialize_Signature(signatureBinn, &s);
            free(signatureBinn);
            cipher c;
            unsigned char *cipherBinn = base64_decode(b64Cipher, strlen(b64Cipher),&outLen);
            deserialize_Cipher(cipherBinn, &c);
            free(cipherBinn);

            // Computes the message to sign, so the cipher struct
            int c0size = gt_size_bin(c.c0, 1);
            int c1Size = g1_size_bin(c.c1, 1);
            int c2Size = g2_size_bin(c.c2, 1);
            int c3Size = g2_size_bin(c.c3, 1);
            uint8_t mSig[c0size + c1Size + c2Size + c3Size];
            gt_write_bin(mSig, c0size, c.c0, 1);
            g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
            g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
            g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);

            int sock = connectToKGC();
            binn *getPKBinnObj;
            getPKBinnObj = binn_object();
            binn_object_set_str(getPKBinnObj, "opCode", "GPS");
            binn_object_set_str(getPKBinnObj, "ID", sourceAddress);
            send(sock, binn_ptr(getPKBinnObj), binn_size(getPKBinnObj), 0);
            binn_free(getPKBinnObj);

            char bufferGPS[512] = {0};
            int testSize = recv(sock, bufferGPS, 512, 0);
            // printf("%s\n", bufferGPE);
            signature_pk signature_sourcePK;
            size_t out_len_test;
            unsigned char *signature_sourcePKBin = base64_decode(bufferGPS, testSize, &out_len_test);
            deserialize_PKS(signature_sourcePKBin, &signature_sourcePK);

            // We can go for decrypting and verification
            // We can verify directly with the public keys of the sender
            int test = verify(s, signature_sourcePK, mpkSignature, sourceAddress, mSig);
            printf("\nVerification of the key (0 if correct 1 if not) : %d\n", test);
            // if the verif is ok we can continue, otherwise we can stop here
            if(test == 0) {
                // For this we need our Partial Private Keys with the ID used to encrypt the message
                encryption_ppk PartialKeysBob;

                sock = connectToKGC();

                char bufferPPKE[1024] = {0};
                binn* bobPpk;
                bobPpk = binn_object();
                binn_object_set_str(bobPpk, "opCode", "EE");
                binn_object_set_str(bobPpk, "ID", userID);
                send(sock, binn_ptr(bobPpk), binn_size(bobPpk), 0);
                binn_free(bobPpk);

                read(sock, bufferPPKE, 1024);
                deserialize_PPKE(bufferPPKE, &PartialKeysBob);

                // Computes Secret User Keys
                encryption_sk SecretKeysBob;
                g2_null(SecretKeysBob->s1)
                g2_new(SecretKeysBob->s1)

                g1_null(SecretKeysBob->s2)
                g1_new(SecretKeysBob->s2)
                setPriv(encryption_secret, PartialKeysBob, mpkSession, userID, &SecretKeysBob);

                // We can decrypt now
                gt_t decryptedMessage;
                gt_null(decryptedMessage)
                gt_new(decryptedMessage)
                decrypt(c, SecretKeysBob, encryptionPk, mpkSession, userID, &decryptedMessage);

                char aeskDecrypted[crypto_secretbox_KEYBYTES];
                get_key(aeskDecrypted, decryptedMessage);

                size_t size_cipher;
                unsigned char *ciphertext = base64_decode(b64Encrypted, strlen(b64Encrypted), &size_cipher);
                unsigned char decrypted[size_cipher];
                memset(decrypted, 0, size_cipher);

                // TODO récupérer d'ailleurs
                size_t nonceSize;
                unsigned char* nonceAES = base64_decode(b64Nonce, strlen(b64Nonce), &nonceSize);
                decrypt_message(decrypted, ciphertext, nonceAES, aeskDecrypted, size_cipher);
                printf("Decrypted message : %s\n", decrypted);
                free(ciphertext);
                free(nonceAES);
            }

            free(signature_sourcePKBin);
            free(b64Nonce);
            free(b64Cipher);
            free(b64Encrypted);
            free(b64Signature);
            free(sourceAddress);
        }
        free(charUserChoice);
        free(userID);
    }
    core_clean();
}