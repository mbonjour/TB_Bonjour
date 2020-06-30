//
// Created by mbonjour on 14.05.20.
//

#ifndef TEST_RELIC_SIGNATUREPOC_H
#define TEST_RELIC_SIGNATUREPOC_H
#include <stdio.h>
#include <relic.h>
#include <string.h>

#define MESSAGE_SPACE 257

typedef struct mpkStructSig mpkStructSig;
struct mpkStructSig {
    g1_t P, Ppub;
};

typedef struct PKSig PKSig;
struct PKSig {
    g1_t Ppub;
};

typedef struct SKSig SKSig;
struct SKSig {
    g2_t D;
    bn_t x;
};

typedef struct PPKSig PPKSig;
struct PPKSig {
    g2_t D;
};

typedef struct Signature signature;
struct Signature {
    g1_t U;
    g2_t V;
};

void functionH2(g2_t* to_point, char* bytes_from, int len_bytes);
void functionH3(g2_t* to_point, char* bytes_from, int len_bytes);

void setupSig(int i, mpkStructSig *pStruct, bn_t *ptr);

void extractSig(mpkStructSig mpk, bn_t msk, char* ID, PPKSig * partialKeys);

void setSecSig(bn_t* x);

void setPubSig(bn_t x, mpkStructSig mpkSession, PKSig* PKtoGen);

void setPrivSig(bn_t x,PPKSig d, mpkStructSig mpk, char* ID, SKSig * secretKeys);

void sign(unsigned char* m, SKSig sk, PKSig pk, unsigned char* ID, mpkStructSig mpk, signature* s);

int verify(signature s, PKSig pk, mpkStructSig mpk, char* ID, unsigned char* m);

#endif //TEST_RELIC_SIGNATUREPOC_H
