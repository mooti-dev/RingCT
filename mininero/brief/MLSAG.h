/*
 * File:   MLSAG.h
 * Author: Shen Noether <shen.noether@gmx.com>
 * (c.f. MLSAG2.py rather than MLSAG.py)
 * Created on January 11, 2016, 3:35 PM
 */


#include <cstddef>
#include <mutex>
#include <vector>
#include <tuple>
#include <string.h>

#include "generic-ops.h"

#include "crypto-ops.h"
#include "random.h"
#include "keccak.h"

#include "MiniNero.h"
#include "PaperWallet.h"

#ifndef MLSAG_H
#define	MLSAG_H

namespace crypto {

//vector of public or secret keys in byte form
struct keyV {
    std::vector<key> keys;
    int rows;
public :
    void push(key a) {
        this->rows++;
        this->keys.resize(this->rows);
        this->keys[this->rows-1] = a;
    }
    keyV () {
        this->keys.resize(rows);
        this->rows = 0;
    }   
     keyV (int rows) {
        this->keys.resize(rows);
        this->rows = rows;
    }
};

//vector of key vectors (key matrix)
struct keyM {
    int cols;
    int rows;
    std::vector<keyV> column;
public :
    void push(keyV a) {
        if (rows < a.rows) {
            rows = a.rows;
        }
        this->cols++;
        this->column.resize(this->cols);
        this->column[this->cols-1] = a;
    }
    
keyM () {
    this->column.resize(9);
    this->cols = cols;
    this->rows = 0;

    int i = 0;
    for (i = 0 ; i < cols ; i++) {
        this->column[i].keys.resize(0);
        this->column[i].rows = 0;
    }
}
keyM (int rows, int cols) {
    this->column.resize(cols);
    this->cols = cols;
    this->rows = rows;

    int i = 0;
    for (i = 0 ; i < cols ; i++) {
        this->column[i].keys.resize(rows);
        this->column[i].rows = rows;
    }
}};

//concatenates all keys in a key vector
inline char * join(keyV kv ) {
    char * rv = (char * )malloc(32 * kv.rows);
    int i = 0;
    for (i = 0 ; i < kv.rows ; i++) {
        memcpy(rv + (32 * i), kv.keys[i].data, 32 );
    }
    return rv;
}

//concatenates all keys in a keyMatrix 
//(use this before hashing)
inline char * join(keyM km) {
    char * rv = (char * )malloc(32 * km.rows * km.cols);
    int i = 0;
    int j = 0;
    for (i = 0 ; i < km.cols ; i++) {
        for (j = 0 ; j < km.rows ; j++) {
            memcpy(rv + km.rows * 32 * i + (32 * j), km.column[i].keys[j].data, 32 );
        }
    }
    return rv;
}


inline void printkv(keyV a) {
    int j = 0;
    printf("[");
    for (j = 0 ; j < a.rows ; j++) {
        printk(a.keys[j]);
        if (j < a.rows - 1) {
            printf(",");
        }
    }
    printf("]");
}


inline void printkm(keyM a) {
    int j = 0;
    printf("[");
    for (j = 0 ; j < a.cols; j++) {
        printkv(a.column[j]);
        if (j < a.cols- 1) {
            printf(",");
        }
    }
    printf("]");
}


class mlsag {
public:
    mininero MiniNero;
    paperwallet PaperWallet;
    mlsag ();
    mlsag (const mlsag& orig);
    virtual ~mlsag ();
    
    keyV hashKeyVector(keyV);
    keyV vScalarMultBase(keyV);
    keyV keyImageV(keyV);
    keyV skvGen(std::size_t);
    keyM skmGen(int, int);
    std::tuple<keyV, key, keyM> mlsag::MLSAG_Gen(keyM, keyV, int);
    bool mlsag::MLSAG_Ver(keyM, keyV, key, keyM);


private:

};

}

#endif	/* MLSAG_H */

