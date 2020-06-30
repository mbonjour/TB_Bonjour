
#ifndef AES_UTILS_H
#define AES_UTILS_H

#include "sodium.h"
#include "relic.h"

char* encrypt_message(const char* m, unsigned char* key, unsigned char* nonce, unsigned char* cipher, unsigned long long* cipher_len, const size_t* m_len);
void decrypt_message(unsigned char* decrypted, unsigned char* cipher, unsigned char* nonce, unsigned char* key, unsigned long long cipher_len);
void get_key(char *aesk, gt_t originalM);

#endif //AES_UTILS_H