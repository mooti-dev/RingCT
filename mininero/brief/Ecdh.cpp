/*
 * File:   Ecdh.cpp
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 * This is a basic Ecdh which can be used to 
 * share amounts between sender of the commitment 
 * and receiver. 
 * 
 * Note that I only use each shared secret once, but you 
 * can hash the shared secret to get more share secrets.
 *
 */

#include "Ecdh.h"

namespace crypto {

ecdh::ecdh() {
}

ecdh::ecdh(const ecdh& orig) {
}

ecdh::~ecdh() {
}

/* return two shared secrets ss1 and ss2, and a sec / pub belonging to sender (ephembytes / ephempub) which is only for sending purposes
*
* Input: receivers public key
*/
std::tuple<key, key, key, key> ecdh::ecdhGen(key P) {
    key ephembytes, ephempub;
    std::tie(ephembytes, ephempub) = PaperWallet.skpkGen();
    //receiver pk * sender sk = shared pub
    key sspub = MiniNero.scalarmultKey(P, ephembytes);
    key ss1 = MiniNero.cn_fast_hash(sspub.data, 32);
    key ss2 = MiniNero.cn_fast_hash(ss1.data, 32);
    return std::make_tuple(ephembytes, ephempub, ss1, ss2);
}


/*  Given the ephempub, the receiver can generate ss1, ss2
* which are the two shared secrets.
*/
std::tuple<key, key> ecdh::ecdhRetrieve(key x, key pk) {
    key sspub = MiniNero.scalarmultKey(pk, x);
    key ss1 = MiniNero.cn_fast_hash(sspub.data, 32);
    key ss2 = MiniNero.cn_fast_hash(ss1.data, 32);
    return std::make_tuple(ss1, ss2);
}

}