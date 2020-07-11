#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include <arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include<pthread.h>
#include <netinet/tcp.h>

#include "cipherPOC.h"
#include "signaturePOC.h"
//TODO: sauvegarder les master secret pour permettre au serveur de récréer son état en cas de redémarrage
/***
 * Main du KGC de l'infrastructure, doit permettre de recevoir des requêtes et de les traiter pour l'extraction des clés partielles, et pour délivrer des clés publiques demandées
*/

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

bn_t masterSecret;
g2_t msk;
// MPK struct, Master Public Key structure to store
mpkStruct mpkSession;
mpkStructSig mpkSignature;

char** generate_fields(int numberOfFields, int sizeOfFields) {
    char** options = malloc(numberOfFields*sizeof(char *));
    for(int i = 0; i < numberOfFields; i++)
        options[i] = malloc(sizeOfFields);
    return options;
}

void free_fields(char ** options, int numberOfFields, int sizeOfFields) {
    for(int i = 0; i < numberOfFields; i++) {
        memset(options[i], 0, sizeOfFields);
        free(options[i]);
    }
    memset(options, 0, numberOfFields*sizeof(char*));
    free(options);
}

void split(char** tokensDest, char* initialString, char* delim){
    char* token = strtok(initialString, delim);

    // Extract code tokens[0] et l'ID (ou payload) tokens[1]
    // loop through the string to extract all other tokens
    int i = 0;
    while( token != NULL ) {
        // TODO change when using bytes ? Or maybe base64 all along to have strings
        strcpy(tokensDest[i], token);
        token = strtok(NULL, delim);
        ++i;
    }
}

// Codes : Signature extraction (SE), Encryption Extraction (EE), Get Public kex Encryption (GPE), Get Public kex Signature (GPS),
// Put Public key Encryption (PKE), Put Public key Signature (PKS)
void* socketThread(void *arg){
    int newSocket = *((int *)arg);
    // TODO change number of bytes to read ?
    char client_message[1024];
    recv(newSocket , client_message , 1024 , 0);
    // TODO : change the size of fields to be able to put the data received
    char** tokens = generate_fields(2, 64);
    pthread_mutex_lock(&lock);
    split(tokens, client_message, ":");
    pthread_mutex_unlock(&lock);
    // Remove \r\n from the last token
    // TODO check if still necessary with client implemented
    //tokens[1][strcspn(tokens[1], "\r\n")] = 0;
    //Prepare structs for the possibilities
    PPKSig myPartialKeysSig;
    PPK myPartialKeys;
    if(strcmp(tokens[0], "SE") == 0){
        printf("Code : SE\n");
        //The sender needs to extract (via KGC) and setPriv to get his private key and sign the message
        extractSig(mpkSignature, masterSecret, tokens[1], &myPartialKeysSig);
        binn* obj;
        obj = binn_object();
        serialize_PPKS(obj, myPartialKeysSig);
        send(newSocket,binn_ptr(obj),binn_size(obj),0);
        binn_free(obj);
    }
    if(strcmp(tokens[0], "EE") == 0){
        printf("Code : EE\n");
        //The receiver needs to extract (via KGC) and setPriv to get his private key and decrypt the cipher
        extract(mpkSession, msk, tokens[1], &myPartialKeys);
        /*size_t sizePartialKeys = 0;
        size_t sizePartialKeysD1 = g2_size_bin(myPartialKeys.d1, 1);
        size_t sizePartialKeysD2 = g1_size_bin(myPartialKeys.d2, 1);
        uint8_t partialKeyToSend[sizePartialKeysD1 + 1 + sizePartialKeysD2]; // +1 pour le séparateur
        g2_write_bin(partialKeyToSend, sizePartialKeysD1, myPartialKeys.d1,1);
        strcpy(&partialKeyToSend[sizePartialKeysD1], ".");

        g1_write_bin(partialKeyToSend, sizePartialKeysD2, myPartialKeys.d2,1);
        */
        binn *obj;
        obj = binn_object();
        serialize_PPKE(obj, myPartialKeys);
        send(newSocket,binn_ptr(obj),binn_size(obj),0);
        binn_free(obj);
    }
    if(strcmp(tokens[0], "GPE") == 0){
        printf("Code : GPE\n");
        char path[strlen(tokens[1])+11];
        strcpy(path, "encryption/");
        strcat(path, tokens[1]);
        // Open files to store the public keys of the users
        printf("Path : %s\n", path);
        FILE* publicKeysEncryptionFile = fopen(path, "r");
        if(publicKeysEncryptionFile == NULL) {
            printf("Error creating/opening required files!");
            // exit(1);
        }
        //TODO take binary data instead
        char** fileTokens = generate_fields(3, 64);
        char fileContent[64];
        //fscanf(publicKeysEncryptionFile,"%s", &fileContent);
        //TODO fread when struct get saved
        while (fgets(fileContent, sizeof(fileContent), publicKeysEncryptionFile)) {
            /* note that fgets don't strip the terminating \n, checking its
               presence would allow to handle lines longer that sizeof(line) */
            printf("%s", fileContent);
        }
        split(fileTokens, fileContent, ":");
        printf("From File : %s:%s:%s\n", fileTokens[0], fileTokens[1], fileTokens[2]);

        //send(newSocket,buffer,strlen(buffer),0);
        fclose(publicKeysEncryptionFile);
        free_fields(fileTokens,3,64);
        publicKeysEncryptionFile = NULL;
    }
    if(strcmp(tokens[0], "GPS") == 0){
        printf("Code : GPS\n");
        char path[strlen(tokens[1])+10];
        strcpy(path, "signature/");
        strcat(path, tokens[1]);
        printf("Path : %s\n", path);
        FILE* publicKeySignature = fopen(path, "r");
        if(publicKeySignature == NULL) {
            printf("Error creating/opening required files!");
            // exit(1);
        }
        //TODO take binary data instead
        char* fileTokens[2];
        fscanf(publicKeySignature,"%s:%s", fileTokens[0], fileTokens[1]);
        printf("From file : %s:%s\n", fileTokens[0], fileTokens[1]);

        //send(newSocket,buffer,strlen(buffer),0);
        fclose(publicKeySignature);
        publicKeySignature = NULL;
    }
    if(strcmp(tokens[0], "PKE") == 0){
        printf("Code : PKE\n");
        char* payload = tokens[1];

        char** payloadTokens = generate_fields(3, 64);
        split(payloadTokens, payload, ",");

        char path[strlen(payloadTokens[0])+11];
        strcpy(path, "encryption/");
        strcat(path, payloadTokens[0]);
        // Open files to store the public keys of the users
        printf("Path : %s\n", path);
        FILE* publicKeysEncryptionFile = fopen(path, "w");
        if(publicKeysEncryptionFile == NULL) {
            printf("Error creating/opening required files!");
            // exit(1);
        }

        printf("%s:%s:%s\n", payloadTokens[0], payloadTokens[1], payloadTokens[2]);
        //TODO : fwrite struct of public key created
        fprintf(publicKeysEncryptionFile,"%s:%s:%s\n", payloadTokens[0], payloadTokens[1], payloadTokens[2]);
        fclose(publicKeysEncryptionFile);
        publicKeysEncryptionFile = NULL;
        free_fields(payloadTokens, 3, 64);
    }
    if(strcmp(tokens[0], "PKS") == 0){
        printf("Code : PKS\n");
        char* payload = tokens[1];

        char** payloadTokens = generate_fields(2,64);
        split(payloadTokens, payload, ",");

        char path[strlen(payloadTokens[0])+10];
        strcpy(path, "signature/");
        strcat(path, payloadTokens[0]);
        printf("Path : %s\n", path);
        FILE* publicKeySignature = fopen(path, "w");
        if(publicKeySignature == NULL) {
            printf("Error creating/opening required files!");
            // exit(1);
        }
        //TODO : fwrite struct of public key created
        printf("%s:%s\n", payloadTokens[0], payloadTokens[1]);
        fprintf(publicKeySignature,"%s:%s\n", payloadTokens[0], payloadTokens[1]);
        fclose(publicKeySignature);
        publicKeySignature = NULL;
        free_fields(payloadTokens, 2, 64);
    }
    if(strcmp(tokens[0], "PK") == 0){
        printf("Code : PK\n");
        char* payload = tokens[1];

        char** payloadTokens = generate_fields(2,64);
        split(payloadTokens, payload, ",");

        char path[strlen(payloadTokens[0])+10];
        strcpy(path, "signature/");
        strcat(path, payloadTokens[0]);
        printf("Path : %s\n", path);
        FILE* publicKeySignature = fopen(path, "w");
        if(publicKeySignature == NULL) {
            printf("Error creating/opening required files!");
            // exit(1);
        }
        //TODO : fwrite struct of public key created

        printf("%s:%s\n", payloadTokens[0], payloadTokens[1]);
        fprintf(publicKeySignature,"%s:%s\n", payloadTokens[0], payloadTokens[1]);
        fclose(publicKeySignature);
        publicKeySignature = NULL;
        free_fields(payloadTokens, 2, 64);
    }
    if(strcmp(tokens[0], "HELO")==0){
        printf("Code : HELO\n");
        binn *obj, *list;
        obj = binn_object();
        list = binn_list();
        serialize_MPKS(obj, mpkSignature);
        binn_list_add_object(list,obj);
        binn_free(obj);
        obj = binn_object();
        serialize_MPKE(obj, mpkSession);
        binn_list_add_object(list, obj);
        binn_free(obj);
        printf("Size of this packet = %d\n", binn_size(list));
        FILE* publicKeysEncryptionFile = fopen("testMPK", "w");
        if(publicKeysEncryptionFile == NULL) {
            printf("Error creating/opening required files!");
            // exit(1);
        }
        //TODO : fwrite struct of public key created
        fwrite(binn_ptr(list), binn_size(list),1,publicKeysEncryptionFile);
        fclose(publicKeysEncryptionFile);
        size_t bytesSent = send(newSocket, binn_ptr(list), binn_size(list),0);
        printf("Bytes sent : %zu\n", bytesSent);
    }
    free_fields(tokens, 2, 64);
    printf("Exit socketThread \n");
    //fflush(newSocket);
    close(newSocket);
    pthread_exit(NULL);
}

int main() {
    if(core_init() == RLC_ERR){
        printf("RELIC INIT ERROR !\n");
    }
    if(pc_param_set_any() == RLC_OK){
        // Server doing this once
        pc_param_print();
        // Setup the encrypting and signing parameters for KGC
        //TODO : Check if a config file exists, if yes take the parameters to not create again the secrets and all of that
        printf("Security : %d\n", pc_param_level());

        // Master secret key of KGC for encrypting
        g2_null(msk)
        g2_new(msk)

        setup(256, &mpkSession, &msk);

        // Master key of KGC for signing
        bn_null(masterSecret)
        bn_new(masterSecret)

        setupSig(256, &mpkSignature, &masterSecret);
        printf("Setup successful !\n");

        // Setupping server connection to accept requests from user (https://dzone.com/articles/parallel-tcpip-socket-server-with-multi-threading)
        int serverSocket, newSocket;
        struct sockaddr_in serverAddr;
        struct sockaddr_storage serverStorage;
        socklen_t addr_size;

        //Create the socket. 
        serverSocket = socket(PF_INET, SOCK_STREAM, 0);
        // Configure settings of the server address struct
        // Address family = Internet 
        serverAddr.sin_family = AF_INET;
        //Set port number, using htons function to use proper byte order 
        serverAddr.sin_port = htons(10003);
        //Set IP address to localhost 
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        //Set all bits of the padding field to 0 
        memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
        //Bind the address struct to the socket 
        bind(serverSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
        //Listen on the socket, with 40 max connection requests queued 
        if(listen(serverSocket,50)==0)
            printf("Listening\n");
        else
            printf("Error\n");
        pthread_t tid[60];
        int i = 0;
        while(1){
            //Accept call creates a new socket for the incoming connection
            addr_size = sizeof serverStorage;
            newSocket = accept(serverSocket, (struct sockaddr *) &serverStorage, &addr_size);
            //for each client request creates a thread and assign the client request to it to process
            //so the main thread can entertain next request
            if( pthread_create(&tid[i++], NULL, socketThread, &newSocket) != 0 )
            printf("Failed to create thread\n");
            // TODO: create a pool of threads who can receive requests
            if( i >= 50){
                i = 0;
                while(i < 50){
                    pthread_join(tid[i++],NULL);
                }
                i = 0;
            }
        }
    }
    core_clean();
}