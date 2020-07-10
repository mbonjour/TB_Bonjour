//
// Created by mbonjour on 14.05.20.
//

#ifndef TEST_RELIC_CIPHERPOC_H
#define TEST_RELIC_CIPHERPOC_H
#include <stdio.h>
#include <relic.h>
#include <string.h>
#include "utils/binn.h"

#define MESSAGE_SPACE 257

typedef struct mpkStruct mpkStruct;
struct mpkStruct {
    g1_t g, g1;
    g2_t g2;
    g2_t u[MESSAGE_SPACE];
    g2_t v[MESSAGE_SPACE];
};

typedef struct PK PK;
struct PK {
    g2_t X;
    g1_t Y;
};

typedef struct SK SK;
struct SK {
    g1_t s2;
    g2_t s1;
};

typedef struct PPK PPK;
struct PPK {
    g1_t d2;
    g2_t d1;
};

typedef struct Cipher cipher;
struct Cipher {
    gt_t c0;
    g1_t c1;
    g2_t c2, c3;
};

void setup(int i, mpkStruct *pStruct, g2_t *ptr);

void F(const char *var, g2_t* suite, g2_t *result);

void extract(mpkStruct mpk, g2_t msk, char* ID, PPK* partialKeys);

void setSec(bn_t* x);

void setPub(bn_t x, mpkStruct mpkSession, PK* PKtoGen);

void setPriv(bn_t x,PPK d, mpkStruct mpk, char* ID, SK* secretKeys);

void encrypt(gt_t m, PK pk, unsigned char* ID, mpkStruct mpk, cipher* c);

void decrypt(cipher c, SK sk, PK pk, mpkStruct  mpk, char* ID, gt_t* m);

void serialize_MPKE(binn* obj, mpkStruct mpke);
void deserialize_MPKE(binn* obj, mpkStruct* newMpk);

void serialize_PPKE(binn* obj, PPK ppke);
void deserialize_PPKE(void* buffer, PPK* newPpk);

void serialize_PKE(binn* obj, PK pk);
void deserialize_PKE(void* buffer, PK* newPk);

#endif //TEST_RELIC_CIPHERPOC_H
