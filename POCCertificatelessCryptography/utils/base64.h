/**
 * @file base64.h
 * @author https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 * @date 13 juillet 2020
 * @brief File to encode/decode base64
 */

#ifndef POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H
#define POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H

#include <glob.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Encode data bytes to base64 format
 * @param src Buffer of data bytes to encode
 * @param len Length of the data to encode
 * @param out_len The size of the returned base64 encoded data
 * @return A pointer to the encoded data (needed to be freed)
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len);
/**
 * @brief Decode data bytes to base64 format
 * @param src Buffer of data encoded to decode
 * @param len Length of the data to decode
 * @param out_len The size of the returned data
 * @return A pointer to the decoded data (needed to be freed)
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len);

#endif //POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H
