#include "mctiny.h"

void mctiny_pk2block(unsigned char *out,const unsigned char *pk,int rowpos,int colpos)
{
  int i,j;
  unsigned char bit;

  colpos *= mctiny_X;
  rowpos *= mctiny_Y;

  for (i = 0;i < mctiny_BLOCKBYTES;++i) out[i] = 0;

  for (i = 0;i < mctiny_Y;++i) {
    if (rowpos+i < 0) continue;
    if (rowpos+i >= mctiny_COLBITS) continue;

    for (j = 0;j < mctiny_X;++j) {
      if (colpos+j < 0) continue;
      if (colpos+j >= mctiny_ROWBITS) continue;

      bit = pk[mctiny_ROWBYTES*(rowpos+i)+(colpos+j)/8];
      bit = 1&(bit>>((colpos+j)&7));
      bit <<= ((i*mctiny_X+j)&7);
      out[(i*mctiny_X+j)/8] |= bit;
    }
  }
}

void mctiny_mergepieces(unsigned char *synd3,const unsigned char (*synd2)[mctiny_PIECEBYTES])
{
  int i,p,j;
  unsigned char bit;

  for (i = 0;i < mctiny_COLBYTES;++i) synd3[i] = 0;

  for (p = 0;p < mctiny_PIECES;++p) {
    for (i = 0;i < mctiny_Y*mctiny_V;++i) {
      j = p*mctiny_Y*mctiny_V+i;
      if (j >= mctiny_COLBITS) continue;
      bit = 1&(synd2[p][i/8]>>(i&7));
      synd3[j/8] ^= bit<<(j&7);
    }
  }
}
