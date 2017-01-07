/*
 * File:   Converter.cpp
 * Author: Shen Noether <shen.noether@gmx.com>
 * 
 * The point of this file is just to provide some 
 * conversion utilities for representing amounts 
 * once the commitment scheme in Ring CT is in use
 *
 */

#include "Converter.h"

namespace crypto {

    converter::converter() {
    }

    converter::converter(const converter& orig) {
    }

    converter::~converter() {
    }

    //Converts from a uint long long to a 32 byte hex
    key converter::d2h(xmr_amount val) {
        key amounth = MiniNero.sc_zero();
        int i = 0, byte = 0;
        while (val != 0) {
            amounth.data[i] = (unsigned char)(val & 0xFF);
            i++;
            val /= 256;
        }
        return amounth;
    }
    
    //uint long long to binary representation
    bits converter::d2b(xmr_amount val) {
        bits amountb;
        int i = 0;
        while (val != 0) {
            amountb.bit[i] = val & 1;
            i++;
            val >>= 1;
        }
        while (i < 64) {
            amountb.bit[i] = 0;
            i++;
        }
        return amountb;
    }
    
    //hex to uint long long
    xmr_amount converter::h2d(key test) {
        xmr_amount vali = 0;
        int j = 0;
        for (j = 7 ; j >=0 ; j-- ) {
            vali  = (xmr_amount)(vali * 256 + (unsigned char) test.data[j]) ;
        }
     
        return vali;
    }
    
    //hex to binary (as a vector of 0's, and 1's)
    bits converter::h2b(key test) {
        bits amountb2;
        int val = 0, i = 0, j = 0;
        for (j = 0 ; j < 8 ; j++ ) {
            val = (unsigned char) test.data[j];
            i = 8 * j;
            while (val != 0) {
                amountb2.bit[i] = val & 1;
                i++;
                val >>= 1;
            }
            while (i < 8 * (j+1)) {
                amountb2.bit[i] = 0;
            }
        }        
        return amountb2;
    }

    //binary to hex
    key converter::b2h(bits amountb2) {
        
        key amountdh = MiniNero.sc_zero(); 
        int byte, i, j;
        for (j = 0 ; j < 8 ; j++ ) {
            byte = 0;
            //val = (unsigned char) test[j];
            i = 8 * j;
        for (i = 7 ; i > -1 ; i--) {
                byte = byte * 2 + amountb2.bit[8 * j + i];
            }
            amountdh.data[j] = (unsigned char) byte;
        }
        return amountdh;
    }
    
    //binary to uint long long
    xmr_amount converter::b2d(bits amountb) {
        
        xmr_amount vali = 0;
        int j = 0;
        for (j = 63 ; j >=0 ; j-- ) {
            vali  = (xmr_amount)(vali * 2 + amountb.bit[j]) ;
        }
        return vali; 
    }
    
    //prints a uint long long 
    void converter::printCryptoInt(xmr_amount vali){
        printf("x: %"PRIu64"\n", vali);
    }
    
    //prints a binary array of 0's and 1's
     void converter::printBits(bits amountb){   
         int i = 0;
        for (int i = 0 ; i < 64 ; i++) {
            printf("%d", amountb.bit[i]);
        }    
        printf("\n");
    }
}