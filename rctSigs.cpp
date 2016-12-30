// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "rctSigs.h"
using namespace crypto;
using namespace std;

namespace rct {


//Borromean (c.f. gmax/andytoshi's paper)
// https://github.com/Blockstream/borromean_paper
// Section 3.3.1
boroSig genBorromean(key64 x, key64 P1, key64 P2, bits indices) {
    key64 L[2], c[2], s[2], alpha, P[2];
    int naught = 0, prime = 0, ii = 0, jj=0;
    for (ii = 0 ; ii < 64 ; ii++) {
        naught = indices[ii]; prime = (indices[ii] + 1) % 2;
        copy(P[0][ii], P1[ii]); //could probably user pointers  
        copy(P[1][ii], P2[ii]);
        skGen(alpha[ii]);
        scalarmultBase(L[naught][ii], alpha[ii]);
        c[prime][ii] = hash_to_scalar(L[naught][ii]);
        skGen(s[prime][ii]);
        addKeys2(L[prime][ii], s[prime][ii], c[prime][ii], P[prime][ii]);
    }
    boroSig bb; 
    bb.ee = hash_to_scalar(L[1]); //or L[1]..
    key LL, cc;
    for (jj = 0 ; jj < 64 ; jj++) {
        naught = indices[jj]; prime = (indices[jj] + 1) % 2;
        if (!indices[jj]) {
            sc_mulsub(bb.s0[jj].bytes, x[jj].bytes, bb.ee.bytes, alpha[jj].bytes);
            copy(bb.s1[jj], s[1][jj]);
        } else {
            copy(bb.s0[jj], s[0][jj]);
            addKeys2(LL, bb.s0[jj], bb.ee, P[0][jj]); //different L0
            cc = hash_to_scalar(LL);
            sc_mulsub(bb.s1[jj].bytes, x[jj].bytes, cc.bytes, alpha[jj].bytes);
        }
    }
    return bb;
}

//see above. 
bool verifyBorromean(boroSig bb, key64 P1, key64 P2) {
    key64 Lv1, chash;  key LL;
    int ii = 0;
    for (ii = 0 ; ii < 64 ; ii++) {
        addKeys2(LL, bb.s0[ii], bb.ee, P1[ii]);
        chash[ii] = hash_to_scalar(LL);
        addKeys2(Lv1[ii], bb.s1[ii], chash[ii], P2[ii]);
    }
    
    key eeComputed = hash_to_scalar(Lv1); //hash function fine
    return equalKeys(eeComputed, bb.ee);
}

//Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
//These are aka MG signatutes in earlier drafts of the ring ct paper
// c.f. http://eprint.iacr.org/2015/1098 section 2.
// keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i
// Gen creates a signature which proves that for some column in the keymatrix "pk"
//   the signer knows a secret key for each row in that column
// Ver verifies that the MG sig was created correctly
keyV keyImageV(const keyV &xx) {
    keyV II(xx.size());
    int i = 0;
    for (i = 0; i < xx.size(); i++) {
        II[i] = scalarmultKey(hashToPoint(scalarmultBase(xx[i])), xx[i]);
    }
    return II;
}


//Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
//This is a just slghtly more efficient version than the ones described below
//(will be explained in more detail in Ring Multisig paper
//These are aka MG signatutes in earlier drafts of the ring ct paper
// c.f. http://eprint.iacr.org/2015/1098 section 2.
// keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i
// Gen creates a signature which proves that for some column in the keymatrix "pk"
//   the signer knows a secret key for each row in that column
// Ver verifies that the MG sig was created correctly
mgSig MLSAG_Gen(key message, const keyM & pk, const keyV & xx, const int index, int dsRows) {
    mgSig rv;
    int rows = pk[0].size();
    int cols = pk.size();
    if (cols < 2) {
        printf("Error! What is c if cols = 1!");
    }
    int i = 0, j = 0, ii = 0;
    key c, c_old, L, R, Hi;
    sc_0(c_old.bytes);
    vector<geDsmp> Ip(dsRows);
    rv.II = keyV(dsRows);
    keyV alpha(rows);
    keyV aG(rows);
    rv.ss = keyM(cols, aG);
    keyV aHP(dsRows);
    keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
    toHash[0] = message;
    DP("here1");
    for (i = 0; i < dsRows; i++) {
        skpkGen(alpha[i], aG[i]); //need to save alphas for later..
        Hi = hashToPoint(pk[index][i]);
        aHP[i] = scalarmultKey(Hi, alpha[i]);
        toHash[3 * i + 1] = pk[index][i];
        toHash[3 * i + 2] = aG[i];
        toHash[3 * i + 3] = aHP[i];
        rv.II[i] = scalarmultKey(Hi, xx[i]);
        precomp(Ip[i].k, rv.II[i]);
    }
    int ndsRows = 3 * dsRows ; //non Double Spendable Rows (see identity chains paper)
    for (i = dsRows, ii = 0 ; i < rows ; i++, ii++) {
        skpkGen(alpha[i], aG[i]); //need to save alphas for later..
        toHash[ndsRows + 2 * ii + 1] = pk[index][i];
        toHash[ndsRows + 2 * ii + 2] = aG[i];
    }

    c_old = hash_to_scalar(toHash);
    

    int oldi = index;

    i = (index + 1) % cols;
    if (i == 0) {
        copy(rv.cc, c_old);
    }
    while (i != index) {

        rv.ss[i] = skvGen(rows);
        sc_0(c.bytes);
        
        for (j = 0; j < dsRows; j++) {
            addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
            hashToPoint(Hi, pk[i][j]);
            addKeys3(R, rv.ss[i][j], Hi, c_old, Ip[j].k);
            toHash[3 * j + 1] = pk[i][j];
            toHash[3 * j + 2] = L;
            toHash[3 * j + 3] = R;
        }
        
        for (j = dsRows, ii = 0 ; j < rows ; j++, ii++) {
            addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
            toHash[ndsRows + 2 * ii + 1] = pk[i][j];
            toHash[ndsRows + 2 * ii + 2] = L;
        }
        c = hash_to_scalar(toHash);
        copy(c_old, c);
        oldi = i;
        i = (i + 1) % cols;

        if (i == 0) {
            copy(rv.cc, c_old);
        }
    }
    

    for (j = 0; j < rows; j++) {
        sc_mulsub(rv.ss[index][j].bytes, c.bytes, xx[j].bytes, alpha[j].bytes);
    }
    return rv;
}

//Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
//This is a just slghtly more efficient version than the ones described below
//(will be explained in more detail in Ring Multisig paper
//These are aka MG signatutes in earlier drafts of the ring ct paper
// c.f. http://eprint.iacr.org/2015/1098 section 2.
// keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i
// Gen creates a signature which proves that for some column in the keymatrix "pk"
//   the signer knows a secret key for each row in that column
// Ver verifies that the MG sig was created correctly
bool MLSAG_Ver(key message, keyM & pk, mgSig & rv, int dsRows) {

    int rows = pk[0].size();
    int cols = pk.size();
    if (cols < 2) {
        printf("Error! What is c if cols = 1!");
        return false;
    }
    int i = 0, j = 0, ii=0;
    key c,  L, R, Hi;
    key c_old = copy(rv.cc);
    vector<geDsmp> Ip(dsRows);
    
    for (i= 0 ; i < dsRows ; i++) {
        precomp(Ip[i].k, rv.II[i]);
    }
    int ndsRows = 3 * dsRows  ; //non Double Spendable Rows (see identity chains paper)
    //keyV toHash(1 + 3 * rows);
    keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
    toHash[0] = message;
    int oldi = 0;
    i = 0;
    
    while (i < cols) {
        sc_0(c.bytes);
        for (j = 0; j < dsRows; j++) {
            addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
            hashToPoint(Hi, pk[i][j]);
            addKeys3(R, rv.ss[i][j], Hi, c_old, Ip[j].k);
            toHash[3 * j + 1] = pk[i][j];
            toHash[3 * j + 2] = L;
            toHash[3 * j + 3] = R;
        }
        for (j = dsRows, ii = 0 ; j < rows ; j++, ii++) {
            addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
            toHash[ndsRows + 2 * ii + 1] = pk[i][j];
            toHash[ndsRows + 2 * ii + 2] = L;
        }
        c = hash_to_scalar(toHash);
        copy(c_old, c);
        oldi = i;
        i = (i + 1);
    }
    sc_sub(c.bytes, c_old.bytes, rv.cc.bytes);
    return sc_isnonzero(c.bytes) == 0;
}



//proveRange and verRange
//proveRange gives C, and mask such that \sumCi = C
//   c.f. http://eprint.iacr.org/2015/1098 section 5.1
//   and Ci is a commitment to either 0 or 2^i, i=0,...,63
//   thus this proves that "amount" is in [0, 2^64]
//   mask is a such that C = aG + bH, and b = amount
//verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
rangeSig proveRange(key & C, key & mask, const xmr_amount & amount) {
    sc_0(mask.bytes);
    identity(C);
    bits b;
    d2b(b, amount);
    rangeSig sig;
    key64 ai;
    key64 CiH;
    int i = 0;
    for (i = 0; i < ATOMS; i++) {
        skGen(ai[i]);
        if (b[i] == 0) {
            scalarmultBase(sig.Ci[i], ai[i]);
        }
        if (b[i] == 1) {
            addKeys1(sig.Ci[i], ai[i], H2[i]);
        }
        subKeys(CiH[i], sig.Ci[i], H2[i]);
        sc_add(mask.bytes, mask.bytes, ai[i].bytes);
        addKeys(C, C, sig.Ci[i]);
    }
    sig.asig = genBorromean(ai, sig.Ci, CiH, b);
    return sig;
}

//proveRange and verRange
//proveRange gives C, and mask such that \sumCi = C
//   c.f. http://eprint.iacr.org/2015/1098 section 5.1
//   and Ci is a commitment to either 0 or 2^i, i=0,...,63
//   thus this proves that "amount" is in [0, 2^64]
//   mask is a such that C = aG + bH, and b = amount
//verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
bool verRange(key & C, rangeSig & as) {
    key64 CiH;
    int i = 0;
    key Ctmp = identity();
    for (i = 0; i < 64; i++) {
        subKeys(CiH[i], as.Ci[i], H2[i]);
        addKeys(Ctmp, Ctmp, as.Ci[i]);
    }
    bool reb = equalKeys(C, Ctmp);
    bool rab = verifyBorromean(as.asig, as.Ci, CiH);
    return (reb && rab);
}

//Ring-ct MG sigs
//Prove:
//   c.f. http://eprint.iacr.org/2015/1098 section 4. definition 10.
//   This does the MG sig on the "dest" part of the given key matrix, and
//   the last row is the sum of input commitments from that column - sum output commitments
//   this shows that sum inputs = sum outputs
//Ver:
//   verifies the above sig is created corretly
mgSig proveRctMG(const ctkeyM & pubs, const ctkeyV & inSk, const ctkeyV &outSk, const ctkeyV & outPk, int index, key txnFeeKey) {
    mgSig mg;
    //setup vars
    int rows = pubs[0].size();
    int cols = pubs.size();
    keyV sk(rows + 1);
    keyV tmp(rows + 1);
    int i = 0, j = 0;
    for (i = 0; i < rows + 1; i++) {
        sc_0(sk[i].bytes);
        identity(tmp[i]);
    }
    keyM M(cols, tmp);
    //create the matrix to mg sig
    for (i = 0; i < cols; i++) {
        M[i][rows] = identity();
        for (j = 0; j < rows; j++) {
            M[i][j] = pubs[i][j].dest;
            addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add input commitments in last row
        }
    }

    sc_0(sk[rows].bytes);
    for (j = 0; j < rows; j++) {
        sk[j] = copy(inSk[j].dest);
        sc_add(sk[rows].bytes, sk[rows].bytes, inSk[j].mask.bytes); //add masks in last row
    }
    for (i = 0; i < cols; i++) {
        for (j = 0; j < outPk.size(); j++) {
            subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
        }
        //subtract txn fee output in last row
        subKeys(M[i][rows], M[i][rows], txnFeeKey);
    }


    for (j = 0; j < outPk.size(); j++) {
        sc_sub(sk[rows].bytes, sk[rows].bytes, outSk[j].mask.bytes); //subtract output masks in last row..
    }
    key message = cn_fast_hash(outPk);
    return MLSAG_Gen(message, M, sk, index, rows);
}

//Ring-ct MG sigs
//Prove:
//   c.f. http://eprint.iacr.org/2015/1098 section 4. definition 10.
//   This does the MG sig on the "dest" part of the given key matrix, and
//   the last row is the sum of input commitments from that column - sum output commitments
//   this shows that sum inputs = sum outputs
//Ver:
//   verifies the above sig is created corretly
bool verRctMG(mgSig mg, ctkeyM & pubs, ctkeyV & outPk, key txnFeeKey) {
    //setup vars
    int rows = pubs[0].size();
    int cols = pubs.size();
    keyV tmp(rows + 1);
    int i = 0, j = 0;
    for (i = 0; i < rows + 1; i++) {
        identity(tmp[i]);
    }
    keyM M(cols, tmp);

    //create the matrix to mg sig
    for (j = 0; j < rows; j++) {
        for (i = 0; i < cols; i++) {
            M[i][j] = pubs[i][j].dest;
            addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add Ci in last row
        }
    }
    for (i = 0; i < cols; i++) {
        for (j = 0; j < outPk.size(); j++) {
            subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
        }
        //subtract txn fee output in last row
        subKeys(M[i][rows], M[i][rows], txnFeeKey);
    }
    key message = cn_fast_hash(outPk);
    DP("message:");
    DP(message);
    return MLSAG_Ver(message, M, mg, rows);
}

//These functions get keys from blockchain
//replace these when connecting blockchain
//getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
//populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
//   the return value are the key matrix, and the index where inPk was put (random).
void getKeyFromBlockchain(ctkey & a, size_t reference_index) {
    a.mask = pkGen();
    a.dest = pkGen();
}

//These functions get keys from blockchain
//replace these when connecting blockchain
//getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
//populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
//   the return value are the key matrix, and the index where inPk was put (random).
tuple<ctkeyM, xmr_amount> populateFromBlockchain(ctkeyV inPk, int mixin) {
    int rows = inPk.size();
    ctkeyM rv(mixin, inPk);
    int index = randXmrAmount(mixin);
    int i = 0, j = 0;
    for (i = 0; i < mixin; i++) {
        if (i != index) {
            for (j = 0; j < rows; j++) {
                getKeyFromBlockchain(rv[i][j], (size_t)randXmrAmount(1000));
            }
        }
    }
    return make_tuple(rv, index);
}

//These functions get keys from blockchain
//replace these when connecting blockchain
//getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
//populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
//   the return value are the key matrix, and the index where inPk was put (random).
xmr_amount populateFromBlockchainSimple(ctkeyV & mixRing, ctkey & inPk, int mixin) {
    int index = randXmrAmount(mixin);
    int i = 0;
    for (i = 0; i < mixin; i++) {
        if (i != index) {
            getKeyFromBlockchain(mixRing[i], (size_t)randXmrAmount(1000));
        } else {
            mixRing[i] = inPk;
        }
    }
    return index;
}

//RingCT protocol
//genRct:
//   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
//   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//   Also contains masked "amount" and "mask" so the receiver can see how much they received
//verRct:
//   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
//decodeRct: (c.f. http://eprint.iacr.org/2015/1098 section 5.1.1)
//   uses the attached ecdh info to find the amounts represented by each output commitment
//   must know the destination private key to find the correct amount, else will return a random number
//   Note: For txn fees, the last index in the amounts vector should contain that
//   Thus the amounts vector will be "one" longer than the destinations vectort

rctSig genRct(ctkeyV & inSk, ctkeyV  & inPk, const keyV & destinations, const vector<xmr_amount> amounts, const int mixin) {
    rctSig rv;
    rv.outPk.resize(destinations.size());
    rv.rangeSigs.resize(destinations.size());
    rv.ecdhInfo.resize(destinations.size());

    int i = 0;
    keyV masks(destinations.size()); //sk mask..
    ctkeyV outSk(destinations.size());
    for (i = 0; i < destinations.size(); i++) {
        //add destination to sig
        rv.outPk[i].dest = copy(destinations[i]);
        //compute range proof
        rv.rangeSigs[i] = proveRange(rv.outPk[i].mask, outSk[i].mask, amounts[i]);
#ifdef DBG
        verRange(rv.outPk[i].mask, rv.rangeSigs[i]);
#endif

        //mask amount and mask
        rv.ecdhInfo[i].mask = copy(outSk[i].mask);
        rv.ecdhInfo[i].amount = d2h(amounts[i]);
        ecdhEncode(rv.ecdhInfo[i], destinations[i]);

    }
    //set txn fee
    rv.txnFee = amounts[destinations.size()];
    key txnFeeKey = scalarmultH(d2h(rv.txnFee));
    int index;
    tie(rv.mixRing, index) = populateFromBlockchain(inPk, mixin);
    rv.MG = proveRctMG(rv.mixRing, inSk, outSk, rv.outPk, index, txnFeeKey);
    return rv;
}

//RingCT protocol
//genRct:
//   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
//   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//   Also contains masked "amount" and "mask" so the receiver can see how much they received
//verRct:
//   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
//decodeRct: (c.f. http://eprint.iacr.org/2015/1098 section 5.1.1)
//   uses the attached ecdh info to find the amounts represented by each output commitment
//   must know the destination private key to find the correct amount, else will return a random number
bool verRct(rctSig & rv) {
    int i = 0;
    bool rvb = true;
    bool tmp;
    DP("range proofs verified?");

    for (i = 0; i < rv.outPk.size(); i++) {
        tmp = verRange(rv.outPk[i].mask, rv.rangeSigs[i]);
        if (tmp == false) {
            return false;
        }
        DP(tmp);
        rvb = (rvb && tmp);
    }

    //compute txn fee
    key txnFeeKey = scalarmultH(d2h(rv.txnFee));

    bool mgVerd = verRctMG(rv.MG, rv.mixRing, rv.outPk, txnFeeKey);


    DP("mg sig verified?");
    DP(mgVerd);
    bool tb = true;

    return (rvb && mgVerd);
}

//RingCT protocol
//genRct:
//   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
//   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//   Also contains masked "amount" and "mask" so the receiver can see how much they received
//verRct:
//   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
//decodeRct: (c.f. http://eprint.iacr.org/2015/1098 section 5.1.1)
//   uses the attached ecdh info to find the amounts represented by each output commitment
//   must know the destination private key to find the correct amount, else will return a random number
xmr_amount decodeRct(rctSig & rv, key & sk, int i) {
    //mask amount and mask
    ecdhDecode(rv.ecdhInfo[i], sk);
    key mask = rv.ecdhInfo[i].mask;
    key amount = rv.ecdhInfo[i].amount;
    key C = rv.outPk[i].mask;
    DP("C");
    DP(C);
    key Ctmp;
    addKeys2(Ctmp, mask, amount, H);
    DP("Ctmp");
    DP(Ctmp);
    if (equalKeys(C, Ctmp) == false) {
        printf("warning, amount decoded incorrectly, will be unable to spend");
    }
    return h2d(amount);
}

//RingCT protocol
//genRct:
//   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
//   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
//   Also contains masked "amount" and "mask" so the receiver can see how much they received
//verRct:
//   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
//decodeRct: (c.f. http://eprint.iacr.org/2015/1098 section 5.1.1)
//   uses the attached ecdh info to find the amounts represented by each output commitment
//   must know the destination private key to find the correct amount, else will return a random number
xmr_amount decodeRct(sRctSig & rv, key & sk, int i) {
    //mask amount and mask
    ecdhDecode(rv.ecdhInfo[i], sk);
    key mask = rv.ecdhInfo[i].mask;
    key amount = rv.ecdhInfo[i].amount;
    key C = rv.outPk[i].mask;
    DP("C");
    DP(C);
    key Ctmp;
    addKeys2(Ctmp, mask, amount, H);
    DP("Ctmp");
    DP(Ctmp);
    if (equalKeys(C, Ctmp) == false) {
        printf("warning, amount decoded incorrectly, will be unable to spend");
    }
    return h2d(amount);
}

}