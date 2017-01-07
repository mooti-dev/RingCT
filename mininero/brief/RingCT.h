/*
 * File:   RingCT.h
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
#include "MLSAG.h"
#include "Converter.h"
#include "ASNL.h"
#include "PaperWallet.h"
#include "Ecdh.h"


#ifndef RINGCT_H
#define	RINGCT_H

#define ATOMS 64

namespace crypto {

using namespace std;

//commitment pair
struct comm {
    key P; //destination
    key C; //total commitment
    key txid; //a field to reference this commitment
    key sk; //secret key (usually empty)
};

//vector of public commitments (P, C)
struct commV {
    std::vector<comm> comms;
    int rows;
public :
    void push(comm a) {
        this->rows++;
        this->comms.resize(this->rows);
        this->comms[this->rows-1] = a;
    }

    commV() {
        this->comms.resize(0);
        this->rows = 0;
    }
    commV(int rows) {
        this->comms.resize(rows);
        this->rows = rows;
    }
};

//vector of public commitments (P, C)
typedef struct commM {
    int cols;
    int rows;
    std::vector<commV> column;
public :
    void push(commV a) {
        if (rows < a.rows) {
            rows = a.rows;
        }
        this->cols++;
        this->column.resize(this->cols);
        this->column[this->cols-1] = a;
    }

    commM() {
        this->column.resize(0);
        this->cols = 0;
        this->rows = 0;

        int i = 0;
        for (i = 0 ; i < cols ; i++) {
            this->column[i].comms.resize(0);
            this->column[i].rows = 0;
        }
    }
    commM(int rows, int cols) {
        this->column.resize(cols);
        this->cols = cols;
        this->rows = rows;

        int i = 0;
        for (i = 0 ; i < cols ; i++) {
            this->column[i].comms.resize(rows);
            this->column[i].rows = rows;
        }
    }
};

//initializes commitment vector with certain number of rows

//stored in place of usual (x, P)
//Convert to this after block checkpoint
//Also, as far as having access to your money,
//you only need to keep track of these.
struct commPrivate : comm {
    key P; //destination
    key mask; //mask
    xmr_amount amount; //amount
};

//The publically visible range proof
//(Can be probably be thrown away
//   at block checkpoints)
struct commPublic : comm {
    keyV Ci; //bit commitments
    keyV L1; //part of signature
    keyV s2; //part of signature
    key s; //part of signature
};

//Ring CT signature
struct rctSig {
    keyV II;
    key cc;
    keyM ss;
};

class ringct {
public:
    mlsag MLSAG;
    mininero MiniNero;
    converter Converter;
    asnl ASNL;
    ecdh Ecdh;
    paperwallet PaperWallet;
    //Constructors
    ringct ();
    ringct (const ringct& orig);
    virtual ~ringct ();
    //Variables
    xmr_amount amount_in;
    xmr_amount amount_out;
    int n_inputs;
    int n_outputs;
    int rows;
    int mixin;
    int cols;
    std::vector<commPrivate> inputs;//senders column of commitments
    keyV sk;//senders column of secret keys
    keyV Pk; //senders column of pub keys
    keyM PubMatrix;
    commM CM;
    //inputs for mg sig..
    key sumCOut;
    key sumCIn;
    key sumMaskIn; //add to when adding an input
    key sumMaskOut; //add to when adding an output
    //Outputs for MG sig
    rctSig rval;
    //Methods
    key ringct::getHForCT();
    key ringct::sumCi(keyV);
    key ringct::sumSc(keyV);
    void ringct::addColumn();
    std::tuple<commPublic, key>  ringct::genRangeProof(xmr_amount, key);
    commPrivate ringct::testCommitment(xmr_amount);
    void ringct::addInput(commPrivate);
    bool ringct::verRangeProof(key, commPublic);
    void ringct::RCTSign(int);
    bool ringct::RCTVerify(rctSig, keyM);
    xmr_amount ringct::ComputeReceivedAmount(key, key, key, key, key);

};
}
#endif	/* RINGCT_H */

