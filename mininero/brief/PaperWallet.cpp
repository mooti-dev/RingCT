/*
 * File:   PaperWallet.cpp
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 * Created on January 11, 2016, 12:23 PM
 */

#include "PaperWallet.h"

namespace crypto {
mininero MiniNero;

paperwallet::paperwallet() {
}

paperwallet::paperwallet(const paperwallet& orig) {
}

paperwallet::~paperwallet() {
}
//generates a private key,
//also used for random scalars in
//signatures
key paperwallet::skGen() {
    unsigned char tmp[64];
    generate_random_bytes(64, tmp);
    sc_reduce(tmp);
    key res;
    memcpy(&res, tmp, 32);
    return res;
}

//generates a public key
//(used in testing)
key paperwallet::pkGen() {
    unsigned char tmp[64];
    generate_random_bytes(64, tmp);
    sc_reduce(tmp);
    key res;
    memcpy(&res, tmp, 32);
    return MiniNero.scalarmultBase(res);
}

//Gets either 1 or 0 
//This is useful for testing the ASNL's
int paperwallet::getrandbit() {
    unsigned char tmp[1];
    generate_random_bytes(1, tmp);
    //printf("%d", (int)tmp[0] % 2);
    return (int)tmp % 2;
}

//generates a secret key sk and sk * G 
std::tuple<key, key> paperwallet::skpkGen()	{
    key s = this->skGen();
    key P = MiniNero.scalarmultBase(s);
    return std::make_tuple(s, P);
}
}

