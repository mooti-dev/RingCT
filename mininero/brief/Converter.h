/*
 * File:   Converter.h
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 * Provides conversion utilities between 
 * hex, binary array, and uint long long 
 * since these three types are used in Ring CT
 *
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

#include "MiniNero.h"


#ifndef CONVERTER_H
#define	CONVERTER_H

//Number of atomic bits in Monero Amounts
#define ATOMS 64

#undef PRIu64
#define PRIu64 "I64u"

namespace crypto {
    
//Amounts can be represented by this 
typedef uint64_t xmr_amount;
    
struct bits {
    unsigned int bit[ATOMS];
};
    
class converter{
public:
    mininero MiniNero;
    converter ();
    converter (const converter& orig);
    virtual ~converter ();
    key converter::d2h(xmr_amount);
    bits converter::d2b(xmr_amount); 
    xmr_amount converter::h2d(key); 
    bits converter::h2b(key);
    key converter::b2h(bits );
    xmr_amount converter::b2d(bits); 
    void converter::printCryptoInt(xmr_amount);
    void converter::printBits(bits);   
private:

};
}

#endif	/* CONVERTER_H */

