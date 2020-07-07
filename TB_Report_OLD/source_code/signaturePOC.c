//
// Created by mbonjour on 14.05.20.
// Attention : H1 = H2 = H3 dans cette implémentation !!!!
//
#include "signaturePOC.h"

void functionH2(g2_t* to_point, char* bytes_from, int len_bytes){
    uint8_t to_hash[len_bytes + 1];
    to_hash[0] = '\x01';
    memcpy(to_hash + 1, bytes_from, len_bytes);
    g2_map(*to_point, to_hash, len_bytes + 1);
}
void functionH3(g2_t* to_point, char* bytes_from, int len_bytes){
    uint8_t * to_hash[len_bytes + 1];
    to_hash[0] = '\x02';
    memcpy(to_hash + 1, bytes_from, len_bytes);
    g2_map(*to_point, to_hash, len_bytes + 1);
}

void setupSig(int i, mpkStructSig *mpk, bn_t *s){
    bn_t q;
    bn_null(*s)
    bn_new(*s)

    bn_null(q)
    bn_new(q)

    g1_get_ord(q);

    bn_rand_mod(*s, q);
    g1_null(mpk->P)
    g1_new(mpk->P)
    g1_null(mpk->Ppub)
    g1_new(mpk->Ppub)
    g1_get_gen(mpk->P);
    g1_mul(mpk->Ppub, mpk->P, *s);

    bn_free(q)
}

void extractSig(mpkStructSig mpk, bn_t msk, char* ID, PPKSig * partialKeys) {
    g2_t qa;
    g2_null(qa)
    g2_new(qa)

    g2_null(partialKeys->D)
    g2_new(partialKeys->D)

    g2_map(qa, ID, strlen(ID));
    g2_mul(partialKeys->D, qa, msk);

    // Test correctnes
    gt_t test1, test2;
    gt_null(test1)
    gt_null(tet2)
    gt_new(test1)
    gt_new(test2)

    pc_map(test1, mpk.P, partialKeys->D);
    pc_map(test2, mpk.Ppub, qa);

    if (gt_cmp(test2, test1) == RLC_EQ) {
        printf("The partial private key extraction is correct !\n");
    }
   g2_free(qa)
}

void setSecSig(bn_t* x){
    bn_t q;
    bn_null(q)
    bn_new(q)
    bn_null(*x)
    bn_new(*x)
    g1_get_ord(q);
    bn_rand_mod(*x, q);

    bn_free(q)
}

void setPubSig(bn_t x, mpkStructSig mpkSession, PKSig* PKtoGen){
    g1_null(PKtoGen->Ppub)
    g1_new(PKtoGen->Ppub)
    g1_mul(PKtoGen->Ppub, mpkSession.P, x);
}

void setPrivSig(bn_t x, PPKSig d, mpkStructSig mpk, char* ID, SKSig * secretKeys){
    g2_null(secretKeys->D)
    g2_new(secretKeys->D)

    bn_null(secretKeys->x)
    bn_new(secretKeys->x)

    g2_copy(secretKeys->D, d.D);
    bn_copy(secretKeys->x, x);
}

void sign(unsigned char* m, SKSig sk, PKSig pk, unsigned char* ID, mpkStructSig mpk, signature* s){
    bn_t r, q;
    bn_null(r)
    bn_new(r)
    bn_null(q)
    bn_new(q)
    g1_get_ord(q);
    bn_rand_mod(r, q);

    //Computes U
    g1_null(s->U)
    g1_new(s->U)
    g1_mul(s->U, mpk.P, r);

    g2_null(s->V)
    g2_new(s->V)
    g2_copy(s->V, sk.D);

    g2_t h2, h3;
    g2_null(h2)
    g2_null(h3)
    g2_new(h2)
    g2_new(h3)

    int PKsize = g1_size_bin(pk.Ppub, 1);
    int USize = g1_size_bin(s->U, 1);
    int lenConcat1 = strlen(ID) + strlen(m) + PKsize + USize;
    int lenConcat2 = strlen(ID) + strlen(m) + PKsize;

    uint8_t concat1[lenConcat1], concat2[lenConcat2];
    strcpy(concat1, m);
    strcpy(concat2, m);
    strcpy(&concat1[strlen(m)], ID);
    strcpy(&concat2[strlen(m)], ID);

    g1_write_bin(&concat1[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);
    g1_write_bin(&concat2[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);

    g1_write_bin(&concat1[strlen(ID) + strlen(m) + PKsize], USize, s->U, 1);

    functionH2(h2, concat1, lenConcat1);
    functionH3(h3, concat2, lenConcat2);

    g2_mul(h2, h2, r);
    g2_mul(h3, h3, sk.x);

    g2_add(s->V, s->V, h2);
    g2_add(s->V, s->V, h3);

    bn_free(r)
    bn_free(q)
    g2_free(h2)
    g2_free(h3)
}

int verify(signature s, PKSig pk, mpkStructSig mpk, char* ID, unsigned char* m){
    int result = 1;
    g2_t qa;
    g2_null(qa)
    g2_new(qa)
    g2_map(qa, ID, strlen(ID));
    gt_t leftOperand, rightOperand, temp;
    gt_null(leftOperand)
    gt_null(rightOperand)
    gt_null(temp)
    gt_new(leftOperand)
    gt_new(rightOperand)
    gt_new(temp)
    pc_map(leftOperand, mpk.P, s.V);
    pc_map(rightOperand, mpk.Ppub, qa);


    g2_t h2, h3;
    g2_null(h2)
    g2_null(h3)
    g2_new(h2)
    g2_new(h3)

    int PKsize = g1_size_bin(pk.Ppub, 1);
    int USize = g1_size_bin(s.U, 1);
    int lenConcat1 = strlen(ID) + strlen(m) + PKsize + USize;
    int lenConcat2 = strlen(ID) + strlen(m) + PKsize;

    uint8_t concat1[lenConcat1], concat2[lenConcat2];
    strcpy(concat1, m);
    strcpy(concat2, m);
    strcpy(&concat1[strlen(m)], ID);
    strcpy(&concat2[strlen(m)], ID);

    g1_write_bin(&concat1[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);
    g1_write_bin(&concat2[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);
    g1_write_bin(&concat1[strlen(ID) + strlen(m) + PKsize], USize, s.U, 1);

    functionH2(h2, concat1, lenConcat1);
    functionH3(h3, concat2, lenConcat2);

    pc_map(temp, s.U, h2);
    gt_mul(rightOperand, rightOperand, temp);
    gt_null(temp)
    gt_new(temp)
    pc_map(temp, pk.Ppub, h3);
    gt_mul(rightOperand, rightOperand, temp);

    if (gt_cmp(leftOperand, rightOperand) == RLC_EQ) {
        result = 0;
    }

    return result;
}
