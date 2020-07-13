// Utils function for encrypting / decrypting AES_GCM
#include "aesUtils.h"

void encrypt_message(const char* m, unsigned char* key, unsigned char* nonce, unsigned char* cipher, unsigned long long* cipher_len, const size_t* m_len){
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