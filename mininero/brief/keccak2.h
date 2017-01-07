// keccak.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>


#ifndef KECCAK2_H
#define KECCAK2_H
#include <cstddef>
#include <stdint.h>
#include <string.h>

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

//Changed inlen to size_t (s.n. MRL labs)
// compute a keccak hash (md) of given byte length from "in"
int keccak2(const uint8_t *in, std::size_t inlen, uint8_t *md, int mdlen);

// update the state
void keccak2f(uint64_t st[25], int norounds);

//Changed inlen to size_t (s.n. MRL labs)
void keccak21600(const uint8_t *in, std::size_t inlen, uint8_t *md);

#endif
