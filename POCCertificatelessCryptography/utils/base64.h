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

unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len);

unsigned char * base64_decode(const unsigned char *src, size_t len,
                              size_t *out_len);

#endif //POCCERTIFICATELESSCRYPTOGRAPHY_BASE64_H
