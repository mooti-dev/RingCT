/*
 * File:   Ecdh.h
 * Author: Shen Noether <shen.noether@gmx.com>
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
#include "PaperWallet.h"


#ifndef ECDH_H
#define	ECDH_H

namespace crypto {
class ecdh {
public:
    paperwallet PaperWallet;
    mininero MiniNero;
    ecdh ();
    ecdh (const ecdh& orig);
    virtual ~ecdh ();
    std::tuple<key, key, key, key> ecdh::ecdhGen(key);
    std::tuple<key, key> ecdh::ecdhRetrieve(key, key);

private:

};
}

#endif	/* ECDH_H */

