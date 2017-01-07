/*
 * File:   MiniNero.cpp
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 * Created on January 11, 2016, 11:55 AM
 */

#include "MiniNero.h"

namespace crypto {

mininero::mininero() {
}

mininero::mininero(const mininero& orig) {
}

mininero::~mininero() {
}

//takes scalar a and returns aG where G is
//ed25519 basepoint..
key mininero::scalarmultBase(key sec) {
    ge_p3 point;
    sc_reduce32(sec.data); //yes this is important..
    ge_scalarmult_base(&point, sec.data);
    key rv;
    ge_p3_tobytes(rv.data, &point);
    return rv;
}

//gives num * pk where pk is a curve point and num is a scalar
key mininero::scalarmultKey(key pk, key num) {
    ge_p3 A;
    ge_p2 R;
    ge_frombytes_vartime(&A, pk.data);
    ge_scalarmult(&R, num.data, &A);
    key rv;
    ge_tobytes(rv.data, &R);
    return rv;
}

//Computes cn_fast_hash (i.e. keccak)
//But with nicer inputs / outputs
//l is 32 for one key, 64 for 2 keys, etc...
key mininero::cn_fast_hash(const void * data, std::size_t l) {
    uint8_t md2[32];
    int j = 0;
    key hash;
    keccak2((uint8_t *) data, l, md2, 32);
    for (j= 0 ; j < 32 ; j++) {
        hash.data[j] = (unsigned char)md2[j];
    }
    sc_reduce32(hash.data);
    return hash;
}


//Computes cn_fast_hash (i.e. keccak)
//But with nicer inputs / outputs
//l is 32 for one key, 64 for 2 keys, etc...
key mininero::cn_fast_hash(key in) {
    uint8_t md2[32];
    int j = 0;
    key hash;
    keccak2((uint8_t *) in.data, 32, md2, 32);
    for (j= 0 ; j < 32 ; j++) {
        hash.data[j] = (unsigned char)md2[j];
    }
    sc_reduce32(hash.data);
    return hash;
}

//Checks if two curve points are equal
//There is probably a better way to check if two curve points are equal..
bool mininero::ge_quick_check(key a, key b) {
    return sc_isnonzero(sc_sub_keys(this->cn_fast_hash(a), this->cn_fast_hash(b)).data);
}

//takes in a secret or public key
//Computes it's hash as a scalar
//then returns the scalar times the basepoint..
key mininero::hashToPoint_cn(key hexVal) {
    key HP = this->cn_fast_hash(hexVal.data, (std::size_t)32);
    return this->scalarmultBase(HP);
}

//returns "0" (the key)
key mininero::sc_zero() {
    key z = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    return z;
}

//returns "0" on the curve
key mininero::identity() {
    key z = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    return scalarmultBase(z);
}

//adds two keys (a + b) mod l
key mininero::sc_add_keys(key a, key b) {
    key rv;
    sc_add(rv.data, a.data, b.data);
    return rv;
}

//subs two keys (a + b) mod l
key mininero::sc_sub_keys(key a, key b) {
    key rv;
    sc_sub(rv.data, a.data, b.data);
    return rv;
}

//because sc_mulsub is backwards from how I usually think of it
key mininero::sc_mulsub_keys(key a, key b, key c) {
    key rv;
    sc_mulsub(rv.data, b.data, c.data, a.data);
    return rv;
}

//add Keys (adds two elliptic curve points)
//A + B
key mininero::addKeys(key A, key B) {
    ge_p3 B2, A2;
    ge_frombytes_vartime(&B2, B.data);
    ge_frombytes_vartime(&A2, A.data);
    ge_cached tmp2;
    ge_p3_to_cached(&tmp2, &B2);
    ge_p1p1 tmp3;
    ge_add(&tmp3, &A2, &tmp2);
    key rv;
    ge_p1p1_to_p3(&A2, &tmp3);
    ge_p3_tobytes(rv.data, &A2);
    return rv;
}

//subtract Keys (subtracts curve points)
//r = A - B
key mininero::subKeys(key A, key B) {
    ge_p3 B2, A2;
    ge_frombytes_vartime(&B2, B.data);
    ge_frombytes_vartime(&A2, A.data);
    ge_cached tmp2;
    ge_p3_to_cached(&tmp2, &B2);
    ge_p1p1 tmp3;
    ge_sub(&tmp3, &A2, &tmp2);
    key rv;
    ge_p1p1_to_p3(&A2, &tmp3);
    ge_p3_tobytes(rv.data, &A2);
    return rv;
}
//addKeys1
//gives aG + bB where G is basepoint
//a, b, are scalars and B is a curve point.
key mininero::addKeys1(key a, key b, key B) {
    ge_p2 rv;
    ge_p3 B2;
    ge_frombytes_vartime(&B2, B.data);
    ge_double_scalarmult_base_vartime(&rv, b.data, &B2, a.data);
    key rv2;
    ge_tobytes(rv2.data, &rv);
    return rv2;
}

//Does some precomputation so you
 // can add keys faster (see addKeys2)
void mininero::precomp(ge_dsmp rv, key B) {
    ge_p3 B2;
    ge_frombytes_vartime(&B2, B.data);
    ge_dsm_precomp(rv, &B2);
}

//addKeys2
//gives aA + bB with a, b scalars
//and A, B are curve points..
//as we are usually using B as a keyimage,
//which we use over and over again,
//you can do a precomputation with B..
key mininero::addKeys2(key a, key A, key b, ge_dsmp B) {
    ge_p2 rv;
    ge_p3 A2;
    ge_frombytes_vartime(&A2, A.data);
    ge_double_scalarmult_precomp_vartime(&rv, a.data, &A2, b.data, B);
    key rv2;
    ge_tobytes(rv2.data, &rv);
    return rv2;
}


}