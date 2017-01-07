/*
 * File:   MiniNero.h
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 * Created on January 11, 2016, 11:55 AM
 */

#pragma once

#include <cstddef>
#include <mutex>
#include <vector>

#include "generic-ops.h"

#include "crypto-ops.h"
#include "random.h"
#include "keccak2.h"

#ifndef MININERO_H
#define	MININERO_H

namespace crypto {

//can be a public or secret key in byte form
struct key {
    char data[32];
};


//prints a key
//(useful for debugging against python)
inline void printk(key a) {
    int j = 0;
    printf("\"");
    for (j = 0 ; j < 32 ; j++) {
        printf("%02x", (unsigned char)a.data[j]);
    }
    printf("\"");
}

inline void printVer(bool a) {
    printf(" ... %s ... ", a ? "true" : "false");
    }

inline void printa(char * a, int l) {
    int j = 0;
    printf("\"");
    for (j = 0 ; j < l ; j++) {
        printf("%02x", (unsigned char)a[j]);
    }
    printf("\"");
}




class mininero {
public:
    mininero ();
    mininero (const mininero& orig);
    virtual ~mininero ();
    key scalarmultBase(key);
    key scalarmultKey(key, key);
    key hashToPoint_cn(key);
    key cn_fast_hash(const void *, std::size_t);
    key mininero::cn_fast_hash(key);
    key mininero::sc_zero();
    key mininero::identity();
    key mininero::sc_add_keys(key, key);
    key mininero::sc_sub_keys(key, key);
    bool ge_quick_check(key, key) ;
    key sc_mulsub_keys(key, key, key);
    key mininero::addKeys(key, key);
    key mininero::subKeys(key, key);
    key addKeys1(key, key, key);
    void precomp(ge_dsmp, key B);
    key addKeys2(key, key, key, ge_dsmp);

private:


};

}

#endif	/* MININERO_H */

