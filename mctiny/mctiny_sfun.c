#include <stdint.h>
#include <string.h>
#include "crypto_stream_xsalsa20.h"
#include "crypto_sort_int32.h"
#include "hash.h"
#include "mctiny.h"

static const unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];

int mctiny_seedisvalid(const unsigned char *seed)
{
  int i, count;
  uint16_t ind[ mctiny_T*2 ];
  int32_t ind32[ mctiny_T*2 ];

  crypto_stream_xsalsa20((unsigned char *) ind,sizeof ind,nonce,seed);
  /* XXX: replicated servers must agree on endianness */

  for (i = 0; i < mctiny_T*2; i++)
    ind[i] &= mctiny_MMASK;

  count = 0;
  for (i = 0; i < mctiny_T*2; i++)
    if (ind[i] < mctiny_N)
      ind32[ count++ ] = ind[i];
  
  if (count < mctiny_T) return 0;

  crypto_sort_int32(ind32, mctiny_T);

  for (i = 1; i < mctiny_T; i++)
    if (ind32[i-1] == ind32[i])
      return 0;

  return 1;
}

void mctiny_seed2e(unsigned char *e,const unsigned char *seed)
{
  unsigned char *orige = e;
  int i, j, count;
  uint16_t ind[ mctiny_T*2 ];
  int32_t ind32[ mctiny_T*2 ];
  uint64_t e_int[ 1+mctiny_N/64 ];  
  uint64_t one = 1;  
  uint64_t mask;  
  uint64_t val[ mctiny_T ];  

  crypto_stream_xsalsa20((unsigned char *) ind,sizeof ind,nonce,seed);

  for (i = 0; i < mctiny_T*2; i++)
    ind[i] &= mctiny_MMASK;

  count = 0;
  for (i = 0; i < mctiny_T*2; i++)
    if (ind[i] < mctiny_N)
      ind32[ count++ ] = ind[i];
  
  crypto_sort_int32(ind32, mctiny_T);

  for (j = 0; j < mctiny_T; j++)
    val[j] = one << (ind32[j] & 63);

  for (i = 0; i < 1+mctiny_N/64; i++) {
    e_int[i] = 0;

    for (j = 0; j < mctiny_T; j++) {
      mask = i ^ (ind32[j] >> 6);
      mask -= 1;
      mask >>= 63;
      mask = -mask;

      e_int[i] |= val[j] & mask;
    }
  }

  for (i = 0; i < mctiny_N/64; i++) {
    *(uint64_t *) e = e_int[i]; e += 8;
  }

  for (j = 0; j < mctiny_N%64; j+=8) 
    e[ j/8 ] = (e_int[i] >> j) & 0xFF;

  count = 0;
  for (i = 0;i < mctiny_N;++i)
    count += 1&(orige[i/8]>>(i&7));
  if (count != mctiny_T) ; /* internal bug */
}

void mctiny_eblock2syndrome(unsigned char *s,const unsigned char *e,const unsigned char *block,int colpos)
{
  int i,j;
  int epos;
  unsigned char epart[mctiny_XBYTES];
  unsigned char emask,tally;

  for (i = 0;i < mctiny_YBYTES;++i) s[i] = 0;

  if (colpos < 0) return;
  colpos *= mctiny_X;

  /* XXX: can do these shifts more efficiently */
  for (j = 0;j < mctiny_XBYTES;++j) epart[j] = 0;
  for (j = 0;j < mctiny_X;++j) {
    epos = colpos+j;
    if (epos >= mctiny_ROWBITS) continue;
    epos += mctiny_COLBITS;
    emask = 1&(e[epos/8]>>(epos&7));
    epart[j/8] ^= emask<<(j&7);
  }

  for (i = 0;i < mctiny_Y;++i) {
    tally = 0;
    for (j = 0;j < mctiny_XBYTES;++j)
      tally ^= epart[j]&block[j];

    tally ^= tally>>4;
    tally ^= tally>>2;
    tally ^= tally>>1;
    tally &= 1;
    s[i/8] ^= tally<<(i&7);
    block += mctiny_XBYTES;
  }
}

void mctiny_pieceinit(unsigned char *synd2,const unsigned char *e,int p)
{
  int i;
  int epos;
  unsigned char bit;

  for (i = 0;i < mctiny_PIECEBYTES;++i) synd2[i] = 0;

  for (i = 0;i < mctiny_V*mctiny_Y;++i) {
    epos = p*mctiny_V*mctiny_Y+i;
    if (epos < 0) continue;
    if (epos >= mctiny_COLBITS) continue;
    bit = 1&(e[epos/8]>>(epos&7));
    synd2[i/8] ^= bit<<(i&7);
  }
}

void mctiny_pieceabsorb(unsigned char *synd2,const unsigned char *synd1,int i)
{
  int j;
  int outpos;
  unsigned char bit;

  if (i < 0) return;
  if (i >= mctiny_V) return;

  for (j = 0;j < mctiny_Y;++j) {
    bit = 1&(synd1[j/8]>>(j&7));
    outpos = i*mctiny_Y+j;
    synd2[outpos/8] ^= bit<<(outpos&7);
  }
}

void mctiny_finalize(unsigned char *c,unsigned char *k,const unsigned char *synd3,const unsigned char *e)
{
  unsigned char one_ec[1+mctiny_EBYTES+mctiny_CIPHERTEXTBYTES];

  memcpy(c,synd3,mctiny_COLBYTES);

  one_ec[0] = 2;
  memcpy(one_ec+1,e,mctiny_EBYTES);
  hash(c+mctiny_COLBYTES,one_ec,1+mctiny_EBYTES);

  one_ec[0] = 1;
  memcpy(one_ec+1+mctiny_EBYTES,c,mctiny_CIPHERTEXTBYTES);
  hash(k,one_ec,sizeof one_ec);
}
