#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <tuple>
#include <limits>
#include <cstddef>
#include <iostream>
#include "crypto-ops.h"
#include "crypto.h"
#include "keccak.h"

#include "MiniNero.h"
#include "PaperWallet.h"
#include "MLSAG.h"
#include "ASNL.h"
#include "Ecdh.h"
#include "Converter.h"
#include "RingCT.h"

//#include "hash-ops.h"

#define BYTES 64
using namespace crypto;
using namespace std;

int main(int argc, char *argv[]) {
    printf("running Test.cpp\n");

    char * test = "dec";
    paperwallet PaperWallet;
    mininero MiniNero;
    mlsag MLSAG;
    asnl ASNL;
    ecdh Ecdh;
    converter Converter;
printf("testing dec");
        printk(Converter.d2h(2));

    ringct r;
    ringct RingCT;
    if (test == "dec") {
printf("testing dec");
        printk(Converter.d2h(2));
}
    if (test == 'add') {
        key A = {{0x21, 0x0a, 0x42, 0x59, 0xad, 0x82, 0xf0, 0x05, 0x1d, 0xce, 0x9b, 0x5b, 0x65, 0x0b, 0x29, 0x61, 0x24, 0xea, 0x78, 0x39, 0x40, 0x2b, 0xf8, 0x41, 0x49, 0xbf, 0x91, 0xb2, 0x51, 0x23, 0x19, 0x81}};
        key B = {{0x80, 0xee, 0x4f, 0x0f, 0x8f, 0x3f, 0x89, 0xff, 0x3c, 0x76, 0xf8, 0x4b, 0xf7, 0x3e, 0x1c, 0x34, 0x90, 0x45, 0x48, 0x23, 0x1b, 0x5e, 0x48, 0xe9, 0x8b, 0x32, 0xb5, 0x4d, 0xa1, 0x1d, 0x82, 0x20}};
        char * rv = "7107310f12e7bf998d63240748aecc0b3c7a56cf93cada3a56f465371d8c27ee";
        key AB  = MiniNero.addKeys(A, B);
        printk(AB);
    }
    if (test == 'smult') {
        key sk, pk;
        tie(sk, pk) = PaperWallet.skpkGen();
        printf("\ntest\n");
        key p = {{0x87, 0xa6, 0x13, 0x52, 0xd8, 0x6f, 0x5c, 0xb0, 0xe9, 0xd2, 0x27, 0x54, 0x2b, 0x6b, 0x48, 0x70, 0xb9, 0xa3, 0x27, 0xd0, 0x82, 0xd1, 0x5e, 0xa6, 0x4e, 0x04, 0x94, 0xb9, 0xa8, 0x96, 0xc1, 0xac}};
        key pp = MiniNero.scalarmultBase(p);
        printk(pp);
    }
    if (test == 'ch') {
        char th[64] = {0x18, 0xa5, 0xf3, 0xcf, 0x50, 0xae, 0x22, 0x07, 0xd8, 0xcc, 0xd7, 0x01, 0x79, 0xa1, 0x3b, 0x4f, 0xc3, 0x39, 0xd0, 0xcd, 0x6d, 0x91, 0x38, 0xc6, 0xd7, 0x64, 0xf8, 0xe4, 0xce, 0xf8, 0xf0, 0x06, 0xc8, 0x7b, 0x13, 0x67, 0xfe, 0xf3, 0xf0, 0x2e, 0xd5, 0xff, 0xd4, 0x2a, 0x7e, 0xa2, 0x12, 0xc2, 0xb8, 0x89, 0x9a, 0xf3, 0xaf, 0x8f, 0x4b, 0x1e, 0x34, 0x13, 0x9e, 0x1e, 0x39, 0x0f, 0x3a, 0xf1};
        printa(th, 64);
        key h2 = MiniNero.cn_fast_hash(th, 64);
        printf("h2\n");
        printk(h2);
        return 0;
        key h3 = MiniNero.cn_fast_hash(h2.data, 32);
        printf("h3\n");
        printk(h3);
        key h4 = MiniNero.scalarmultBase(h3);
        printf("h4\n");
        printk(h4);
    }
    if (test == 'addKeys') {
        key a = {{0x13, 0xe4, 0x67, 0xe9, 0xc0, 0x03, 0x4e, 0x68, 0x78, 0xaf, 0x5c, 0x80, 0x1a, 0x81, 0xee, 0x05, 0x43, 0xb1, 0x09, 0x6b, 0x5a, 0xb0, 0x13, 0x56, 0xb3, 0x49, 0xcc, 0x32, 0x35, 0xcd, 0x19, 0x09}};
        key A = MiniNero.scalarmultBase(a);
        key b = {{0xcd, 0x43, 0xec, 0x6b, 0x80, 0xdd, 0x5e, 0xa2, 0x66, 0x8e, 0x14, 0x1f, 0xc6, 0xdc, 0x11, 0x91, 0x25, 0x8b, 0x5e, 0xb5, 0x8b, 0xf7, 0xdb, 0xef, 0x9e, 0x64, 0x7a, 0xca, 0x3b, 0xa0, 0x97, 0x07}};
        key B = MiniNero.scalarmultBase(b);
        printk(A);
        printk(B);
        ge_dsmp Bp;
        MiniNero.precomp(Bp, B);
        printk(MiniNero.addKeys1(a, b, B));
        printk(MiniNero.addKeys2(a, A, b, Bp));
    }
    if (test == 'overflow') {
        //keccak code originally used int's as inlen, so had to recode as std::size_t
        std::cout <<  "int: " << std::dec << std::numeric_limits<int>::max();
        std::size_t a = std::numeric_limits<int>::max();
        keyV t = MLSAG.skvGen(a);
        char * z0 = join(t);
    }
    if (test == 'bighash') {
        //std::cout <<  "int: " << std::dec << std::numeric_limits<int>::max();
        //std::size_t a = std::numeric_limits<int>::max();
        keyV t = MLSAG.skvGen(1000000);
        char * z0 = join(t);
        printf("a = ");
        printa(z0, 1000000 * 32);
        key ct= MiniNero.cn_fast_hash(z0, 1000000 * 32);
        printf("\n");
        printk(ct);

    }
    if (test == 'MLSAG') {
        int rows = 4;
        int cols = 1;
        int ind = 0;
        keyM x = MLSAG.skmGen(rows, cols);
        keyV sk = x.column[ind];
        keyM P = keyM(rows, cols);
        int i = 0;
        for ( i = 0 ; i < cols ; i++) {
            P.column[i] = MLSAG.vScalarMultBase(x.column[i]);
        }
        keyV II;
        key cc;
        keyM ss;
        tie(II, cc, ss) = MLSAG.MLSAG_Gen(P, sk, ind);
        printf("\nsig verifies?:");
        printf(" ... %s ... ", MLSAG.MLSAG_Ver(P, II, cc, ss) ? "true" : "false");

    }
    if (test == 'SchnorrNL') {
        key x, P2;
        tie(x, P2) = PaperWallet.skpkGen();
        key P1 = PaperWallet.pkGen();
        key L1, s1, s2;
        tie(L1, s1, s2) = ASNL.GenSchnorrNonLinkable(x, P1, P2, 1);
        printf(" ... %s ... ", ASNL.VerSchnorrNonLinkable(P1, P2, L1, s1, s2) ? "true" : "false");
    }
    if (test == 'ASNL') {
        keyV x = keyV(ATOMS);
        keyV P1 = keyV(ATOMS);
        keyV P2 = keyV(ATOMS);
        bits indi;
        int j = 0;
        for (j = 0 ; j < ATOMS ; j++) {
            indi.bit[j] = PaperWallet.getrandbit();
            x.keys[j] = PaperWallet.skGen();
            if ( indi.bit[j] == 0 ) {
                P1.keys[j] = MiniNero.scalarmultBase(x.keys[j]);
                P2.keys[j] = PaperWallet.pkGen();
            } else {
                P2.keys[j] = MiniNero.scalarmultBase(x.keys[j]);
                P1.keys[j] = PaperWallet.pkGen();
            }
        }
        keyV L1, s2;
        key s;
        std::tie(L1, s2, s) = ASNL.GenASNL(x, P1, P2, indi);
        printVer( ASNL.VerASNL(P1, P2, L1, s2, s));
    }
    if ( test == 'Ecdh') {
        //receiver secret key / public key
        key x1, pk1;
        std::tie(x1, pk1) = PaperWallet.skpkGen();
        //ephempub is public key to create shared key
        key ephem, ephempub, ss1s, ss2s, ss1r, ss2r;
        std::tie(ephem, ephempub, ss1s, ss2s) = Ecdh.ecdhGen(pk1);
        std::tie(ss1r, ss2r) = Ecdh.ecdhRetrieve(x1, ephempub);
        printf("shared secret from sender: ");
        printk( ss1s);
        printf("shared secret calculated by receiver: ");
        printk(ss1r);
    }
    if (test == 'conv') {
        //testing amounts conversions since amounts will be stored as a key,
        //and they also need a binary representation in ring CT for the range proofs,
        //it's sort of important to do it correctly.
        key tval = {{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
        //hex to
        printf("\ntesting hex to conversions");
        xmr_amount t2 = Converter.h2d(tval);
        Converter.printCryptoInt(t2);
        bits t3 = Converter.h2b(tval);
        Converter.printBits(t3);

        //dec to
        printf("\n testing dec to conversions\n");
        key conv1 = Converter.d2h(t2);
        printk(conv1);
        bits conv2 = Converter.d2b(t2);
        Converter.printBits(conv2);

        //bits to
        printf("\n testing bin to conversions\n");
        conv1 = Converter.b2h(conv2);
        t2 = Converter.b2d(conv2);
        printk(conv1);
        Converter.printCryptoInt(t2);
    }
    if (test == 'RingCT') {
        
        
        ringct rct; //declare new object for each sig
        
        key s1, P1;
        tie(s1, P1) = PaperWallet.skpkGen(); //receivers private/ public
        rct.genRangeProof((xmr_amount)500, P1);
       
        //second receiver..
        key s2, P2;
        tie(s2, P2) = PaperWallet.skpkGen(); //receivers private/ public
        rct.genRangeProof((xmr_amount)500, P2);
         
        //Add one input of "1000" tacoshi's
        commPrivate C1 = rct.testCommitment((xmr_amount)1000);
        rct.addInput(C1);
        
        //Add another input "75000" tacoshi
        commPrivate C2 = rct.testCommitment((xmr_amount)75000);
        rct.addInput(C2); 
        
        //Add another two outputs of 50000 and 25000 respect
        key s3, P3;
        tie(s3, P3) = PaperWallet.skpkGen(); //receivers private/ public
        rct.genRangeProof((xmr_amount)50000, P3);            
        //Add another two outputs of 50000 and 25000 respect
        key s4, P4;
        tie(s4, P4) = PaperWallet.skpkGen(); //receivers private/ public
        
        key mask4; commPublic Proof4;
        std::tie(Proof4, mask4) = rct.genRangeProof((xmr_amount)25000, P4);         
        
         //increase mixin 
         rct.addColumn();
         int jj = 0;
         for  (jj = 0 ; jj < 20 ; jj++) {
             rct.addColumn();
             }
            
        //Sign
        rct.RCTSign(10); //at index 10
        
        //Verify
        printVer(rct.RCTVerify(rct.rval, rct.PubMatrix));
        
        //Compute an arbitrary sec / pubkey for passing the amounts
        key es, ep, ss1, ss2;
         std::tie(es, ep, ss1, ss2) = Ecdh.ecdhGen(P4);
        
        //mask the amount:
        key maskedAmount = MiniNero.sc_add_keys(ss1, Converter.d2h((xmr_amount)25000)) ;
        //mask the mask
        key maskedMask = MiniNero.sc_add_keys(ss2, mask4);
        
        
       //Compute Received amounts 
       printf("Finding received amount corresponding to P4");
        xmr_amount amount4= rct.ComputeReceivedAmount(ep, s4, maskedMask, maskedAmount , Proof4.C);
        printf("\n amount is:");
        Converter.printCryptoInt(amount4);
       


    }
    return 0;
}
