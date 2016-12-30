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

#include "rctTypes.h"
#include "rctOps.h"
#include "rctSigs.h"


//Define this flag when debugging to get additional info on the console
//works well on windows at least, not so much on osx..
//#define DBG

#define BYTES 64
using namespace crypto;
using namespace std;
using namespace rct;


int main(int argc, char *argv[]) {

    int HPow2 = -2;
    int Sanity = -1;
    int BORO = 0;
    int MG = 2;
    int RCT = 3;
    int testnum = RCT;

    std::cout<<("Running tests ") << testnum <<endl;
    std::cout.setf(std::ios::boolalpha);

    int j = 0;
    int N = 0;
    if (testnum == HPow2) {
        std::cout << "testing hpow2" << endl;
        key G = scalarmultBase(d2h(1));
        key H = hashToPointSimple(G);
        
        dp(G);
        dp(H);
        return 0;
        bool hpow2 = true;
        for (j = 0 ; j < ATOMS ; j++) {
            if(equalKeys(H, H2[j]) == false) {
                ;
                printf("error!");
                hpow2 = false;
            }
            addKeys(H, H, H);
        }
        dp(hpow2);

    } else if (testnum == -1) {

        std::cout << "\nfail\n" << endl;
        
        key G = scalarmultBase(d2h(1));
        key H = hashToPointSimple(G);
        
        dp(G);
        dp(H);
        dp(hashToPoint(H));


    } else if (testnum == 0) {

        //#borromean signatures true one, false one, C != sum Ci, and one out of the range..
        int N = 64;
        key64 xv;
        key64 P1v;
        key64 P2v;
        bits indi;

        std::cout<<("\n\n boro test")<<endl;
        key L1, s1, s2;

        for (j = 0 ; j < N ; j++) {
            indi[j] = (int)randXmrAmount(2);

            xv[j] = skGen();
            if ( (int)indi[j] == 0 ) {
                P1v[j] = scalarmultBase(xv[j]);
                P2v[j] = pkGen();

            } else {

                P2v[j] = scalarmultBase(xv[j]);
                P1v[j] = pkGen();

            }
        }
        boroSig bb = genBorromean(xv, P1v, P2v, indi);
        
        //#true one
        std::cout<<("This one should verify!")<<endl;

        std::cout<<(verifyBorromean(bb, P1v, P2v))<<endl;
        //#false one
        indi[3] = (indi[3] + 1) % 2;
        std::cout<<("This one should NOT verify!")<<endl;
        boroSig bbad = genBorromean(xv, P1v, P2v, indi);

        std::cout<<(verifyBorromean(bbad, P1v, P2v))<<endl;

    } else if (testnum == 2) {
    
        std::cout<<("\n\nMG sig tests")<<endl;
        //Tests for MG Sigs
        //#MG sig: true one
        N = 3;// #cols
        int   R = 3;// #rows
        keyV xtmp = skvGen(R);
        keyM xm = keyMInit(R, N);// = [[None]*N] #just used to generate test public keys
        keyV sk = skvGen(R);
        keyM P  = keyMInit(R, N);// = keyM[[None]*N] #stores the public keys;
        std::cout<<("MG Sig: this one should verify!")<<endl;
        int ind = 2;
        int i = 0;
        for (j = 0 ; j < R ; j++) {
            for (i = 0 ; i < N ; i++)
            {
                xm[i][j] = skGen();
                P[i][j] = scalarmultBase(xm[i][j]);
            }
        }
        for (j = 0 ; j < R ; j++) {
            sk[j] = xm[ind][j];
        }
        key message = identity();
        mgSig IIccss = MLSAG_Gen(message, P, sk, ind, R-1);
        std::cout<<("Sig verified?")<<endl;
        std::cout<<(MLSAG_Ver(message, P, IIccss, R-1) )<<endl;

        //#MG sig: false one
        std::cout<<("MG Sig: this one should NOT verify!")<<endl;
        N = 3;// #cols
        R = 3;// #rows
        xtmp = skvGen(R);
        keyM xx(N, xtmp);// = [[None]*N] #just used to generate test public keys
        sk = skvGen(R);
        //P (N, xtmp);// = keyM[[None]*N] #stores the public keys;

        ind = 2;
        for (j = 0 ; j < R ; j++) {
            for (i = 0 ; i < N ; i++)
            {
                xx[i][j] = skGen();
                P[i][j] = scalarmultBase(xx[i][j]);
            }
            sk[j] = xx[ind][j];
        }
        sk[2] = skGen();//asume we don't know one of the private keys..
        IIccss = MLSAG_Gen(message, P, sk, ind, R-1);
        std::cout<<("Sig verified?")<<endl;
        std::cout<<(MLSAG_Ver(message, P, IIccss, R-1) )<<endl;
    } else if (testnum == 3) {
        //Ring CT Stuff
        //ct range proofs
        std::cout<<("\n\n Ring CT tests")<<endl;
        std::cout<<("Everything below should verify!")<<endl;
        ctkeyV sc, pc;
        ctkey sctmp, pctmp;

        //add fake input 6000
        //the sc is secret data
        //pc is public data
        tie(sctmp, pctmp) = ctskpkGen(6001);
        sc.push_back(sctmp);
        pc.push_back(pctmp);


        //add fake input 7000
        //sc is secret data
        //pc is public data
        tie(sctmp, pctmp) = ctskpkGen(7000);
        sc.push_back(sctmp);
        pc.push_back(pctmp);


        //this vector corresponds to output amounts
        vector<xmr_amount >amounts;

        //this keyV corresponds to destination pubkeys
        keyV destinations;


        //add output 500
        amounts.push_back(500);
        //add the corresponding destination pubkey
        key Sk, Pk;
        skpkGen(Sk, Pk);
        destinations.push_back(Pk);


        //add output for 12500
        amounts.push_back(12500);
        skpkGen(Sk, Pk);
        //add corresponding destination pubkey
        destinations.push_back(Pk);

        //add txn fee for 1
        //has no corresponding destination..
        amounts.push_back(1);

        std::cout<<("computing ring ct sig with mixin 3")<<endl;

        //compute sig with mixin 3
        rctSig s = genRct(sc, pc, destinations, amounts, 3);

        std::cout<<("test sig verifies?")<<endl;

        //verify ring ct signature
        std::cout<<(verRct(s))<<endl;

        std::cout<<endl<<("decode amounts working?")<<endl;


        //decode received amount corresponding to output pubkey index 1
        std::cout<<(decodeRct(s, Sk, 1))<<endl;

        std::cout<<("\nRing CT with failing MG sig part should not verify!")<<endl;
        std::cout<<("Since sum of inputs != outputs")<<endl;

        amounts[1] = 12501;
        skpkGen(Sk, Pk);
        destinations[1] = Pk;


        //compute rct data with mixin 500
        s = genRct(sc, pc, destinations, amounts, 3);

        //verify rct data
        std::cout<<("test sig verifies?")<<endl;
        std::cout<<(verRct(s))<<endl;

        //decode received amount
        std::cout<<("decode amounts working?")<<endl;
        std::cout<<(decodeRct(s, Sk, 1))<<endl;
    } 
    return 0;
}
