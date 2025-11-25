#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mctiny.h"
#include "randombytes.h"

unsigned char pk[mctiny_PUBLICKEYBYTES];
unsigned char sk[mctiny_SECRETKEYBYTES];
unsigned char c[mctiny_CIPHERTEXTBYTES];
unsigned char k[mctiny_SESSIONKEYBYTES];
unsigned char k2[mctiny_SESSIONKEYBYTES];

unsigned char synd3[mctiny_COLBYTES];
unsigned char synd2[mctiny_PIECES][mctiny_PIECEBYTES];
unsigned char synd1[mctiny_YBYTES];
unsigned char block[mctiny_BLOCKBYTES];
unsigned char e[mctiny_EBYTES];
unsigned char seed[32];

int main(void)
{
  int i,p,colpos;

  mctiny_keypair(pk,sk);
  mctiny_enc(c,k,pk);
  mctiny_dec(k2,c,sk);

  if (memcmp(k,k2,sizeof k) != 0) {
    fprintf(stderr,"mctiny-test: fatal: enc-dec test fails\n");
    exit(111);
  }

  do
    randombytes(seed,sizeof seed);
  while (!mctiny_seedisvalid(seed));

  mctiny_seed2e(e,seed);

  for (p = 0;p < mctiny_PIECES;++p) {
    mctiny_pieceinit(synd2[p],e,p);
    for (i = 0;i < mctiny_V;++i) {
      for (colpos = 0;colpos < mctiny_COLBLOCKS;++colpos) {
        mctiny_pk2block(block,pk,p*mctiny_V+i,colpos);
        mctiny_eblock2syndrome(synd1,e,block,colpos);
        mctiny_pieceabsorb(synd2[p],synd1,i);
      }
    }
  }
  mctiny_mergepieces(synd3,synd2);

  mctiny_finalize(c,k,synd3,e);
  mctiny_dec(k2,c,sk);

  if (memcmp(k,k2,sizeof k) != 0) {
    fprintf(stderr,"mctiny-test: fatal: finalize test fails\n");
    exit(111);
  }

  printf("random pk %02x%02x... sk %02x%02x... c %02x%02x... k %02x%02x...\n"
    ,pk[0],pk[1],sk[0],sk[1],c[0],c[1],k[0],k[1]);

  return 0;
}
