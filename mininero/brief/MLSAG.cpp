/*
 * File:   MLSAG.cpp
 * Author: Shen Noether <shen.noether@gmx.com>
 * (c.f. MLSAG2.py rather than MLSAG.py)
 * Created on January 11, 2016, 3:35 PM
 * Computes "MG" signatures 
 * which are similar to 
 * "vectorized" version of the LWW signature
 * c.f. http://eprint.iacr.org/2015/1098
 */

#include "MLSAG.h"

namespace crypto {
//Synctactic sugar
mlsag::mlsag() {
}

mlsag::mlsag(const mlsag& orig) {
}

mlsag::~mlsag() {
}

//hashes key vector to point..
keyV mlsag::hashKeyVector(keyV v) {
    keyV rv = keyV(v.rows);
    int i = 0;
    for (i = 0 ; i < v.rows ; i++) {
        rv.keys[i] = MiniNero.hashToPoint_cn(v.keys[i]);
    }
    return rv;
}

//does scalarmultBase on entire keyvector
keyV mlsag::vScalarMultBase(keyV v) {
    keyV rv = keyV(v.rows);
    int i = 0;
    for (i = 0 ; i < v.rows ; i++) {
        rv.keys[i] = MiniNero.scalarmultBase(v.keys[i]);
    }
    return rv;
}

//Generates key image from vector of secret key
//i.e. it computes I_j = x_j H(P_j)
keyV mlsag::keyImageV(keyV x) {
    keyV rv = keyV(x.rows);
    int i = 0;
    for (i = 0 ; i < x.rows ; i++) {
        rv.keys[i] = MiniNero.scalarmultKey(MiniNero.hashToPoint_cn(MiniNero.scalarmultBase(x.keys[i])), x.keys[i]);
    }
    return rv;
}

//Generates keyVector of random numbers
//Main purpose is for testing
keyV mlsag::skvGen(std::size_t n) {
    keyV rv = keyV(n);
    std::size_t i = 0;
    for (i = 0 ; i < n ; i++) {
        rv.keys[i] = PaperWallet.skGen();
    }
    return rv;
}

//Generates keymatrix of randoms
//Main purpose is for testing
keyM mlsag::skmGen(int r, int c) {
    keyM rv = keyM(r, c);
    int i = 0;
    for (i = 0 ; i < c ; i++) {
        rv.column[i] = skvGen(r);
    }
    return rv;
}


//Generates MG signature
//See http://eprint.iacr.org/2015/1098
//Follows the python in https://github.com/ShenNoether/MiniNero fairly closely
std::tuple<keyV, key, keyM> mlsag::MLSAG_Gen(keyM pk, keyV xx, int index) {
    int rows = xx.rows;
    int cols = pk.cols;
    printf("Generating MG sig of size %d x %d ", rows, cols);
    keyV c = keyV(cols);
    keyV alpha = skvGen(rows);
    keyV I = keyImageV(xx);
    ge_dsmp Ip[rows];
    keyM L = keyM(rows, cols);
    keyM R = keyM(rows, cols);
    keyM s = keyM(rows, cols);
    std::size_t mrows = rows * cols;


    int i = 0;
    keyV Hi = keyV(rows);
    for (i = 0 ; i < rows ; i++) {
        L.column[index].keys[i] = MiniNero.scalarmultBase(alpha.keys[i]);
        Hi.keys[i] = MiniNero.hashToPoint_cn(pk.column[index].keys[i]);
        R.column[index].keys[i] = MiniNero.scalarmultKey(Hi.keys[i], alpha.keys[i]);
        MiniNero.precomp(Ip[i], I.keys[i]);
    }

    int oldi = index;
    i = (index + 1) % cols;
    pk.column.resize(pk.cols + 2);
    pk.cols += 2;
    pk.column[pk.cols-2] = L.column[oldi];
    pk.column[pk.cols-1] = R.column[oldi];

    char * m1 = join(pk);
    c.keys[i] = MiniNero.cn_fast_hash(m1, 32 * pk.rows * pk.cols);
    int j = 0;

    while (i != index) {
        s.column[i] = this->skvGen(rows);
        for (j = 0 ; j < rows ; j++) {
            L.column[i].keys[j] = MiniNero.addKeys1(s.column[i].keys[j], c.keys[i], pk.column[i].keys[j]);
            Hi.keys[j] = MiniNero.hashToPoint_cn(pk.column[i].keys[j]);
            R.column[i].keys[j] = MiniNero.addKeys2(s.column[i].keys[j], Hi.keys[j], c.keys[i], Ip[j]);
        }

        oldi = i;
        i = (i+1) % cols;
        pk.column[pk.cols-2] = L.column[oldi];
        pk.column[pk.cols-1] = R.column[oldi];
        m1 = join(pk);
        c.keys[i] = MiniNero.cn_fast_hash(m1, 32 * pk.rows * pk.cols);
    }

    for (j = 0 ; j < rows ; j++) {
        //s[index][j] = alpha[j] - c * x[j];
        s.column[index].keys[j] = MiniNero.sc_mulsub_keys(alpha.keys[j], c.keys[index], xx.keys[j]);
        //sc_mulsub(s.column[index].keys[j].data, c.keys[index].data, xx.keys[j].data, alpha.keys[j].data);
    }
    pk.cols-= 2;
    pk.column.resize(pk.cols);
    free(m1);
    return std::make_tuple(I, c.keys[0], s);
}


//Verifies MG signature as above
//c.f. http://eprint.iacr.org/2015/1098
bool mlsag::MLSAG_Ver(keyM pk, keyV I, key c0, keyM s) {
    int rows = I.rows;
    int cols = pk.cols;
    printf("Verifying MG sig of size %d x %d ", rows, cols);
    keyV c = keyV(cols + 1);
    c.keys[0] = c0;
    ge_dsmp Ip[rows];
    keyM L = keyM(rows, cols);
    keyM R = keyM(rows, cols);
    std::size_t mrows = rows * cols;

    int i = 0;
    keyV Hi = keyV(rows);
    for (i = 0 ; i < rows ; i++) {
        MiniNero.precomp(Ip[i], I.keys[i]);
    }

    int oldi = 0;
    i = 0;
    pk.column.resize(pk.cols + 2);
    pk.cols += 2;
    char * m1;

    int j = 0;

    while (i < cols) {
        for (j = 0 ; j < rows ; j++) {
            L.column[i].keys[j] = MiniNero.addKeys1(s.column[i].keys[j], c.keys[i], pk.column[i].keys[j]);
            Hi.keys[j] = MiniNero.hashToPoint_cn(pk.column[i].keys[j]);
            R.column[i].keys[j] = MiniNero.addKeys2(s.column[i].keys[j], Hi.keys[j], c.keys[i], Ip[j]);
        }

        oldi = i;
        i = (i+1) ;
        pk.column[pk.cols-2] = L.column[oldi];
        pk.column[pk.cols-1] = R.column[oldi];
        m1 = join(pk);
        c.keys[i] = MiniNero.cn_fast_hash(m1, 32 * pk.rows * pk.cols);
    }
    pk.cols-= 2;
    pk.column.resize(pk.cols);
    key cc;
    sc_sub(cc.data, c.keys[0].data, c.keys[cols].data);
    free(m1);
    return sc_isnonzero(cc.data) == 0;

}

}