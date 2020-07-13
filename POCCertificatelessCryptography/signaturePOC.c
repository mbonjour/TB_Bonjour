/**
 * @file cipherPOC.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 14 mai 2020
 * @brief All the resources to encrypt/decrypt with a CL-PKC scheme using the RELIC library
 *        Encryption Scheme used : https://eprint.iacr.org/2007/121.pdf
 */
#include "signaturePOC.h"

void functionH2(g2_t* to_point, char* bytes_from, int len_bytes){
    uint8_t to_hash[len_bytes + 1];
    // Hash domain separation adding 1 byte \x01 before the actual data to hash
    to_hash[0] = '\x01';
    memcpy(to_hash + 1, bytes_from, len_bytes);
    g2_map(*to_point, to_hash, len_bytes + 1);
}

void functionH3(g2_t* to_point, char* bytes_from, int len_bytes){
    uint8_t to_hash[len_bytes + 1];
    // Hash domain separation adding 1 byte \x02 before the actual data to hash
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

    bn_zero(q);
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

    gt_set_unity(test1);
    gt_set_unity(test2);
    g2_set_infty(qa);

    gt_free(test2)
    gt_free(test1)
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

    bn_zero(q);
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

    functionH2(&h2, concat1, lenConcat1);
    functionH3(&h3, concat2, lenConcat2);

    g2_mul(h2, h2, r);
    g2_mul(h3, h3, sk.x);

    g2_add(s->V, s->V, h2);
    g2_add(s->V, s->V, h3);

    bn_zero(r);
    bn_zero(q);
    bn_free(r)
    bn_free(q)
    g2_set_infty(h2);
    g2_set_infty(h3);
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

    functionH2(&h2, concat1, lenConcat1);
    functionH3(&h3, concat2, lenConcat2);

    pc_map(temp, s.U, h2);
    gt_mul(rightOperand, rightOperand, temp);
    gt_null(temp)
    gt_new(temp)
    pc_map(temp, pk.Ppub, h3);
    gt_mul(rightOperand, rightOperand, temp);

    if (gt_cmp(leftOperand, rightOperand) == RLC_EQ) {
        result = 0;
    }

    gt_set_unity(leftOperand);
    gt_set_unity(rightOperand);
    gt_set_unity(temp);
    gt_free(leftOperand)
    gt_free(rightOperand)
    gt_free(temp)

    g2_set_infty(h2);
    g2_set_infty(h3);
    g2_set_infty(qa);
    g2_free(h2)
    g2_free(h3)
    g2_free(qa)

    return result;
}
/*
void* serialize_MPKS(mpkStructSig mpks, size_t* totalSize){
    int sizeP = g1_size_bin(mpks.P, 1);
    int sizePpub = g1_size_bin(mpks.Ppub, 1);

    uint8_t* buffer = malloc(((sizeP + sizePpub) * sizeof(char))+(2*sizeof(int)));
    memcpy(buffer, &sizeP, sizeof(int));
    memcpy(buffer+sizeof(int), &sizePpub, sizeof(int));
    g1_write_bin(buffer+(2*sizeof(int)), sizeP, mpks.P, 1);
    //buffer[sizeP] = (uint8_t) ",";
    g1_write_bin(&buffer[sizeP+(2*sizeof(int))], sizePpub, mpks.Ppub, 1);
    *totalSize = sizeP+(2*sizeof(int))+sizePpub;
    return buffer;
}

void deserialize_MPKS(uint8_t* buffer, mpkStructSig* newMpk) {
    int sizeP,sizePpub;
    memcpy(&sizeP, buffer, sizeof(int));
    memcpy(&sizePpub, buffer+sizeof(int), sizeof(int));
    g1_t P,Ppub;
    g1_read_bin(P, buffer+2*sizeof(int), sizeP);
    g1_read_bin(Ppub, buffer+sizeP+2*sizeof(int), sizePpub);
    g1_copy(newMpk->P, P);
    g1_copy(newMpk->Ppub, Ppub);
}
*/
void serialize_MPKS(binn* obj,mpkStructSig mpks) {
    int sizeP = g1_size_bin(mpks.P, 1);
    uint8_t P[sizeP];
    g1_write_bin(P, sizeP, mpks.P, 1);
    binn_object_set_blob(obj, "P", P, sizeP);

    int sizePpub = g1_size_bin(mpks.Ppub, 1);
    uint8_t Ppub[sizePpub];
    g1_write_bin(Ppub, sizePpub, mpks.Ppub, 1);
    binn_object_set_blob(obj, "Ppub", Ppub, sizePpub);
}

void deserialize_MPKS(binn* obj, mpkStructSig* newMpk){

    void *PBin;
    void *PpubBin;
    int sizeP, sizePpub;
    PpubBin = binn_object_blob(obj, "Ppub", &sizePpub);
    PBin = binn_object_blob(obj, "P", &sizeP);

    g1_read_bin(newMpk->P, PBin, sizeP);
    g1_read_bin(newMpk->Ppub, PpubBin, sizePpub);

    //binn_free(obj);
}
void serialize_PPKS(binn* obj, PPKSig ppks){
    int sizeD = g2_size_bin(ppks.D, 1);
    uint8_t P[sizeD];
    g2_write_bin(P, sizeD, ppks.D, 1);
    binn_object_set_blob(obj, "D", P, sizeD);
}
void deserialize_PPKS(void* buffer, PPKSig* newPpk){
    binn *obj;

    obj = binn_open(buffer);
    if (obj == 0) return;
    void *DBin;
    int sizeD;
    DBin = binn_object_blob(obj, "D", &sizeD);

    g2_read_bin(newPpk->D, DBin, sizeD);

    binn_free(obj);
}

void serialize_PKS(binn* obj, PKSig pks){
    int sizePpub = g1_size_bin(pks.Ppub, 1);
    uint8_t Ppub[sizePpub];
    g1_write_bin(Ppub, sizePpub, pks.Ppub, 1);
    binn_object_set_blob(obj, "Ppub", Ppub, sizePpub);
}

void deserialize_PKS(void* buffer, PKSig* newPk){
    binn *obj;

    obj = binn_open(buffer);
    if (obj == 0) return;
    void *PpubBin;
    int sizePpub;
    PpubBin = binn_object_blob(obj, "Ppub", &sizePpub);

    g1_read_bin(newPk->Ppub, PpubBin, sizePpub);

    binn_free(obj);
}