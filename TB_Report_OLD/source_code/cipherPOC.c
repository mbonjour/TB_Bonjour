//
// Created by mbonjour on 14.05.20.
//

#include "cipherPOC.h"

void setup(int k, mpkStruct* mpkSetup, g2_t* msk){
    //TODO nullify struct and init it (g1_new())
    bn_t p, gamma;
    bn_null(p)
    bn_null(gamma)
    bn_new(p)
    bn_new(gamma)

    g1_null(mpkSetup->g)
    g1_null(mpkSetup->g1)
    g2_null(mpkSetup->g2)
    g1_new(mpkSetup->g)
    g1_new(mpkSetup->g1)
    g2_new(mpkSetup->g2)

    g1_get_gen(mpkSetup->g);
    g1_get_ord(p);

    bn_rand_mod(gamma, p);
    g1_mul(mpkSetup->g1, mpkSetup->g, gamma);
    g2_get_gen(mpkSetup->g2);

    for(int i =0; i < MESSAGE_SPACE; ++i){
        g2_null(mpkSetup->u[i])
        g2_null(mpkSetup->v[i])
        g2_new(mpkSetup->u[i])
        g2_new(mpkSetup->v[i])

        //TODO: Changer pour prendre un random nombre et multiplié par g2
        g2_rand(mpkSetup->u[i]);
        g2_rand(mpkSetup->v[i]);
    }

    g2_mul(*msk, mpkSetup->g2, gamma);

    bn_free(gamma)
    bn_free(p)
}

void F(const char *var, g2_t* suite, g2_t *result) {
    uint8_t h[RLC_MD_LEN];
    md_map(h, (uint8_t*) var, strlen(var));

    //TODO: parse h as binary table

    g2_copy(*result, suite[0]);
    g2_t temp;
    g2_null(temp)
    g2_new(temp)
    for(int i = 0; i < 32; ++i){
        uint8_t somebyte = h[i];
        uint8_t currentBit;
        bn_t sheitan;
        bn_null(sheitan)
        bn_new(sheitan)
        for (int j = 0; j < 8; ++j, somebyte >>= 1) {
            currentBit = somebyte & 0x1;
            bn_read_bin(sheitan, &currentBit, 1);
            g2_mul(temp, suite[(i*8) + j], sheitan);
            g2_add(*result, *result, temp)
            g2_null(temp)
        }
    }
}

void extract(mpkStruct mpk, g2_t msk, char* ID, PPK* partialKeys){
    bn_t p, r;
    bn_null(p)
    bn_null(r)
    bn_new(p)
    bn_new(r)

    g1_get_ord(p);
    bn_rand_mod(r,p);

    // Computes d1
    g2_t temp;
    g2_null(temp)
    g2_new(temp)

    F(ID, mpk.u, &temp);
    g2_mul(temp, temp, r);
    g2_add(partialKeys->d1, msk, temp);
    g2_free(temp)

    // Computes d2
    g1_mul(partialKeys->d2, mpk.g, r);

    bn_free(p)
    bn_free(r)
}

void setSec(bn_t* x){
    bn_t p;
    bn_null(p)
    bn_new(p)
    g1_get_ord(p);
    bn_rand_mod(*x, p);
    bn_free(p)
}

void setPub(bn_t x, mpkStruct mpkSession, PK* PKtoGen){
    g2_mul(PKtoGen->X, mpkSession.g2, x);
    g1_mul(PKtoGen->Y, mpkSession.g1, x);
}

void setPriv(bn_t x,PPK d, mpkStruct mpk, char* ID, SK* secretKeys){
    bn_t p, r;
    bn_null(p)
    bn_new(p)
    bn_null(r)
    bn_new(r)
    g1_get_ord(p);
    bn_rand_mod(r, p);

    // Computes s1
    g2_t pointTemp;
    g2_null(pointTemp)
    g2_new(pointTemp)
    g2_mul(secretKeys->s1,d.d1, x);
    F(ID, mpk.u, &pointTemp);
    g2_mul(pointTemp, pointTemp, r);
    g2_add(secretKeys->s1, secretKeys->s1, pointTemp);

    g2_free(pointTemp)

    // Computes s2
    g1_t temp;
    g1_null(temp)
    g1_new(temp)
    g1_mul(secretKeys->s2, d.d2, x);
    g1_mul(temp, mpk.g, r);
    g1_add(secretKeys->s2, secretKeys->s2, temp);
    g1_free(temp)

    bn_free(r)
    bn_free(p)
}

void encrypt(gt_t m, PK pk, unsigned char* ID, mpkStruct mpk, cipher* c){
    bn_t p, s;
    bn_null(p)
    bn_null(s)

    bn_new(p)
    bn_new(s)

    //TODO: Check before ? e(X, g1)/e(g, Y) = 1GT
    g1_get_ord(p);
    bn_rand_mod(s, p);

    // Instantiate our struct
    gt_null(c->c0)
    gt_new(c->c0)

    g1_null(c->c1)
    g1_new(c->c1)

    g2_null(c->c2)
    g2_null(c->c3)
    g2_new(c->c2)
    g2_new(c->c3)

    // Computes C0
    gt_t temp;
    gt_null(temp)
    gt_new(temp)
    pc_map(temp, pk.Y, mpk.g2);
    gt_exp(temp, temp, s);
    gt_mul(c->c0, m, temp)
    gt_free(temp)

    // Computes C1
    g1_mul(c->c1, mpk.g, s);

    // Computes C2
    g2_t pointTemp;
    g2_null(pointTemp)
    g2_new(pointTemp)
    F(ID, mpk.u, &pointTemp);
    g2_mul(c->c2, pointTemp, s);
    g2_free(pointTemp)

    // Computes C3
    g2_t pointTemp2;
    g2_null(pointTemp2)
    g2_new(pointTemp2)

    // Construction of the w bytes object to hash
    int c0size = gt_size_bin(c->c0,1);
    int c1Size = g1_size_bin(c->c1, 1);
    int c2Size = g2_size_bin(c->c2, 1);
    int pkXSize = g2_size_bin(pk.X, 1);
    int pkYSize = g1_size_bin(pk.Y, 1);
    uint8_t w[c0size + c1Size + c2Size + strlen(ID) + pkXSize + pkYSize];
    gt_write_bin(w, c0size, c->c0, 1);
    g1_write_bin(&w[c0size], c1Size, c->c1, 1);
    g2_write_bin(&w[c0size + c1Size], c2Size, c->c2, 1);
    strcpy(&w[c0size + c1Size + c2Size], ID);
    g2_write_bin(&w[c0size + c1Size + c2Size + strlen(ID)], pkXSize, pk.X, 1);
    g1_write_bin(&w[c0size + c1Size + c2Size + strlen(ID) + pkXSize], pkYSize, pk.Y, 1);

    F(w, mpk.v, &pointTemp2);
    g2_mul(c->c3, pointTemp2, s);
    g2_free(pointTemp2)
}

void decrypt(cipher c, SK sk, PK pk, mpkStruct  mpk, char* ID, gt_t* m){
    /* Vesrion fonctionelle (sans vérifications)
     * gt_t numerateur;
    gt_t denominateur;

    pc_map(numerateur, sk.s2, C.c2);
    pc_map(denominateur, C.c1, sk.s1);
    gt_inv(denominateur, denominateur);
    gt_mul(*m, numerateur, denominateur);
    gt_mul(*m, C.c0, *m);
     */
    // Take alpha randomly from Zp
    bn_t alpha, p;
    bn_null(alpha)
    bn_null(p)
    bn_new(alpha)
    bn_new(p)
    g1_get_ord(p);
    bn_rand_mod(alpha, p);
    bn_free(p)

    g2_t pointFv;
    g2_t pointFu;
    g2_null(pointFv)
    g2_null(pointFu)
    g2_new(pointFv)
    g2_new(pointFu)

    // Construction of the w bytes object to hash
    int c0size = gt_size_bin(c.c0,1);
    int c1Size = g1_size_bin(c.c1, 1);
    int c2Size = g2_size_bin(c.c2, 1);
    int pkXSize = g2_size_bin(pk.X, 1);
    int pkYSize = g1_size_bin(pk.Y, 1);
    uint8_t w[c0size + c1Size + c2Size + strlen(ID) + pkXSize + pkYSize];
    gt_write_bin(w, c0size, c.c0, 1);
    g1_write_bin(&w[c0size], c1Size, c.c1, 1);
    g2_write_bin(&w[c0size + c1Size], c2Size, c.c2, 1);
    strcpy(&w[c0size + c1Size + c2Size], ID);
    g2_write_bin(&w[c0size + c1Size + c2Size + strlen(ID)], pkXSize, pk.X, 1);
    g1_write_bin(&w[c0size + c1Size + c2Size + strlen(ID) + pkXSize], pkYSize, pk.Y, 1);
    // Constructs our point
    F(w, mpk.v, &pointFv);
    F(ID, mpk.u, &pointFu);

    gt_t numerateur, denominateur, numerateur2;
    g1_t alphaG, tempNumerateur;
    g2_t Fpoints;
    gt_null(numerateur)
    gt_null(numerateur2)
    gt_null(denominateur)
    g1_null(tempNumerateur)
    gt_new(numerateur)
    gt_new(numerateur2)
    gt_new(denominateur)
    g1_new(tempNumerateur)

    g1_null(alphaG)
    g2_null(Fpoints)
    g1_new(alphaG)
    g2_new(Fpoints)
    // alphaG = alpha * g
    g1_mul(alphaG, mpk.g, alpha);
    g1_add(tempNumerateur, sk.s2, alphaG);
    // numerateur = e(s2 + alphaG, C2)
    pc_map(numerateur, tempNumerateur, c.c2);
    // numerateur2 = e(alphaG, C3)
    pc_map(numerateur2, alphaG, c.c3);
    gt_mul(numerateur, numerateur, numerateur2);

    g2_mul(pointFu, pointFu, alpha);
    g2_mul(pointFv, pointFv, alpha);

    g2_add(Fpoints, sk.s1, pointFu)
    g2_add(Fpoints,Fpoints, pointFv)
    pc_map(denominateur, c.c1, Fpoints);

    gt_inv(denominateur, denominateur);
    gt_mul(*m, numerateur, denominateur);
    gt_mul(*m, c.c0, *m);

    g2_free(pointFv)
    g2_free(pointFu)
    g1_free(alphaG)
    g2_free(Fpoints)
    gt_free(numerateur)
    gt_free(numerateur2)
    g1_free(tempNumerateur)
    gt_free(denominateur)
}