/*
 * File:   RingCT.cpp
 * Author: Shen Noether <shen.noether@gmx.com>
 *
 */

#include "RingCT.h"

namespace crypto {

ringct::ringct() {
    sumMaskIn = MiniNero.sc_zero();
    sumMaskOut = MiniNero.sc_zero();
    sumCIn = MiniNero.identity();
    sumCOut = MiniNero.identity();
    mixin = 0;
    rows = 0;
    cols = 0;
    n_inputs = 0;
    n_outputs = 0;
    sk = keyV();
    Pk = keyV();
    PubMatrix = keyM();
}

ringct::ringct(const ringct& orig) {

    sumMaskIn = MiniNero.sc_zero();
    sumMaskOut = MiniNero.sc_zero()   ;
    mixin = 0;

    sumCIn = MiniNero.identity();
    sumCOut = MiniNero.identity();
    rows = 0;
    cols = 0;
    n_inputs = 0;
    n_outputs = 0;
    sk = keyV();
    Pk = keyV();
    PubMatrix = keyM();
}

ringct::~ringct() {
}

//This returns cn_fast_hash(basepoint)
//which is used in the ring CT commitment scheme
key ringct::getHForCT() {
    key H = {{0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94}}
    ;
    return H;
}

//sums a vector of curve points..
key ringct::sumCi(keyV Cis) {
    key CSum = MiniNero.identity();
    int i = 0;
    for (i = 0 ; i < Cis.rows ; i++) {
        CSum = MiniNero.addKeys(CSum, Cis.keys[i]);
    }
    return CSum;
}

//sums a vector of scalars
key ringct::sumSc(keyV Cis) {
    key CSum = MiniNero.sc_zero();
    int i = 0;
    for (i = 0 ; i < Cis.rows ; i++) {
        CSum = MiniNero.sc_add_keys(CSum, Cis.keys[i]);
    }
    return CSum;
}

//
//generates a range proof using ASNL's
//input should be how much to send, and the destination key
//
//outputs are a range proof (commPublic) and a key (the mask)
std::tuple<commPublic, key> ringct::genRangeProof(xmr_amount b, key dest) {
    commPublic rv;
    amount_out += b;
    rv.P = dest;
    bits bb = Converter.d2b(b); //gives binary form of bb in "digits" binary digits

    //set debug flag..
    printf("\nbits:\n");
    Converter.printBits(bb);

    keyV ai = keyV(ATOMS);
    rv.Ci = keyV(ATOMS);
    keyV CiH = keyV(ATOMS); //this is like Ci - 2^i H

    key a = MiniNero.sc_zero();
    int i = 0;
    key H = getHForCT();

    xmr_amount pow2 = 1;
    for (i = 0 ; i < ATOMS ; i++) {
        ai.keys[i] = PaperWallet.skGen();
        a = MiniNero.sc_add_keys(a, ai.keys[i]); // #creating the total mask since you have to pass this to receiver...
        rv.Ci.keys[i] = MiniNero.addKeys1(ai.keys[i], Converter.d2h((xmr_amount)(bb.bit[i]) * pow2), H);
        CiH.keys[i] = MiniNero.subKeys(rv.Ci.keys[i], MiniNero.scalarmultKey(H, Converter.d2h(pow2)));
        pow2 *= (xmr_amount)2;
    }

    rv.C = sumCi(rv.Ci);

    sumMaskOut = MiniNero.sc_add_keys(sumMaskOut, a);
    sumCOut = MiniNero.addKeys(sumCOut, rv.C);

    std::tie(rv.L1, rv.s2, rv.s) = ASNL.GenASNL(ai, rv.Ci, CiH, bb);
    n_outputs++;
    if (cols == 0) {
        cols ++;
    }
    if (rows == 0) {
        rows++;
    }
    return std::make_tuple(rv, a);
}

//Verifies using the ASNL algo.
bool ringct::verRangeProof(key C, commPublic pr) {
    if (MiniNero.ge_quick_check(sumCi(pr.Ci), C)) {
        puts("Not a range proof for that commitment!");
        return false;
    }
    keyV CiH = keyV(ATOMS);
    int i = 0;
    key H = getHForCT();
    xmr_amount pow2 = 1;
    for (i = 0 ; i < ATOMS ; i++) {
        CiH.keys[i] = MiniNero.subKeys(pr.Ci.keys[i], MiniNero.scalarmultKey(H, Converter.d2h(pow2)));
        pow2 *= (xmr_amount)2; //maybe can replace with an sc_double or something..
    }
    return ASNL.VerASNL(pr.Ci, CiH, pr.L1, pr.s2, pr.s);
}

//generates a random commPrivate for testing purposes
commPrivate ringct::testCommitment(xmr_amount a) {
    commPrivate rv;
    rv.sk = PaperWallet.skGen();
    rv.P = MiniNero.scalarmultBase(rv.sk);
    rv.mask = PaperWallet.skGen();
    rv.amount = a;
    key H= getHForCT();
    rv.C = MiniNero.addKeys1(rv.mask, Converter.d2h(rv.amount) , H);
    return rv;
}

//adds a previous input range proof (in short form)
//to your ring ct sig as an input. 
void ringct::addInput(commPrivate xc) {
    this->inputs.push_back(xc);//asdf careful here
    sk.push(xc.sk);
    this->Pk.push(xc.P);
    this->sumMaskIn = MiniNero.sc_add_keys(this->sumMaskIn, xc.mask);
    this->sumCIn = MiniNero.addKeys(this->sumCIn, xc.C);
    this->amount_in += xc.amount;
    this->n_inputs++;
    this->rows++;
    if (this->cols ==0) {
        this->cols++;
    }
    printf("rows= %d, cols = %d", this->rows, this->cols);
}

//call after adding your inputs, as sumCOut must already be computed
//This is used for increasing the mixin 
//Note that now I am randomly generating other pairs (Pubkey, Commitment)
//when it's actually in use, it will have to get these from the blockchain
void ringct::addColumn() {
    vector<comm> rv;
    keyV tmpP = keyV(n_inputs);
    keyV tmpC = keyV(n_inputs);

    rv.resize(this->n_inputs);
    int i = 0;

    for (i = 0 ; i < n_inputs ; i++) {
        rv[i].P = PaperWallet.pkGen();
        tmpP.keys[i] = rv[i].P;
        rv[i].C = PaperWallet.pkGen();
        tmpC.keys[i] = rv[i].C;
    }

    tmpP.push(MiniNero.subKeys(sumCi(tmpC), sumCOut));//add sumCi to commitment row..
    PubMatrix.push(tmpP); //Append the column to public key matrix.. //asdf careful with the push_back here..
    mixin++;
    cols++;
    printf("rows= %d, cols = %d", rows, cols);
}

//Does MG sig on the data of your public keys and one row corresponding to ring CT
//
void ringct::RCTSign(int index) {

    //printf("here");
    printkv(Pk);
    this->sk.push(MiniNero.sc_sub_keys(sumMaskIn, sumMaskOut));
    this->Pk.push(MiniNero.subKeys(sumCIn, sumCOut));

    printf("\n the right last row?\n");
    printkv(MLSAG.vScalarMultBase(sk));
    printkv(Pk);
    printf("\n\n");


    addColumn();
    printf("pubmatrix %d %d", PubMatrix.cols, PubMatrix.rows);

    printkm(PubMatrix);
    PubMatrix.column[index] = Pk;//puts my pubkeys at index
    std::tie(this->rval.II, this->rval.cc, this->rval.ss) = MLSAG.MLSAG_Gen(this->PubMatrix, this->sk, index);
}

//Verifies MG signature
bool ringct::RCTVerify(rctSig toCheck, keyM Pub) {
    return MLSAG.MLSAG_Ver(Pub, toCheck.II, toCheck.cc, toCheck.ss);
}

//Computes received amounts using ecdh
xmr_amount ringct::ComputeReceivedAmount(key senderEphemPk, key receiverSK, key maskedMask, key maskedAmount, key CSum) {
    key ss1, ss2;
    std::tie(ss1, ss2) = Ecdh.ecdhRetrieve(receiverSK, senderEphemPk);
    key mask = MiniNero.sc_sub_keys(maskedMask, ss2);
    key bH = MiniNero.subKeys(CSum, MiniNero.scalarmultBase(mask)); //bH = C - aG
    key b = MiniNero.sc_sub_keys(maskedAmount, ss1);
    xmr_amount rv = Converter.h2d(b);
    printf("received:");
    Converter.printCryptoInt(rv);
    return rv;
}

}

