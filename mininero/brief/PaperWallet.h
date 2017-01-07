/*
 * File:   PaperWallet.h
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 * Created on January 11, 2016, 12:23 PM
 */

#pragma once

#include <cstddef>
#include <mutex>
#include <vector>
#include <tuple>

#include "generic-ops.h"

#include "crypto-ops.h"
#include "random.h"
#include "keccak.h"
#include "crypto.h"

#include "MiniNero.h"


#ifndef PAPERWALLET_H
#define	PAPERWALLET_H

namespace crypto {
    
static inline void random_scalar(ec_scalar &res) {
    unsigned char tmp[64];
    generate_random_bytes(64, tmp);
    sc_reduce(tmp);
    memcpy(&res, tmp, 32);
}    
    
class paperwallet {
public:
    paperwallet ();
    paperwallet (const paperwallet& orig);
    virtual ~paperwallet ();
    int paperwallet::getrandbit();
    key paperwallet::skGen();
    key paperwallet::pkGen();
    std::tuple<key, key> paperwallet::skpkGen();

private:

};
}

#endif	/* PAPERWALLET_H */

