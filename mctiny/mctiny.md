The `mctiny` library
provides an API for the Classic McEliece cryptosystem
with high-security parameters,
and for various related McTiny functions.
Currently this library uses `mceliece6960119` and `mctiny6960119`,
but the library is designed
so that callers can be agnostic to this choice.

### Classic McEliece

To generate a secret key `sk` and a corresponding public key `pk`:

        #include "mctiny.h"

        unsigned char pk[mctiny_PUBLICKEYBYTES];
        unsigned char sk[mctiny_SECRETKEYBYTES];

        mctiny_keypair(pk,sk);

Given a public key `pk`,
to create a ciphertext `c` that communicates a random session key `k`:

        #include "mctiny.h"

        unsigned char c[mctiny_CIPHERTEXTBYTES];
        unsigned char k[mctiny_SESSIONKEYBYTES];
        const unsigned char pk[mctiny_PUBLICKEYBYTES];

        mctiny_enc(c,k,pk);

Given a secret key `sk` and a ciphertext `c`,
to recover the session key `k`:

        #include "mctiny.h"

        unsigned char k[mctiny_SESSIONKEYBYTES];
        const unsigned char c[mctiny_CIPHERTEXTBYTES];
        const unsigned char sk[mctiny_SECRETKEYBYTES];

        mctiny_dec(k,c,sk);

Classic McEliece is a "quiet" KEM,
meaning that `mctiny_dec` never fails.
Anyone can send ciphertexts to your public key,
or make up random strings as ciphertexts,
producing random session keys from `mctiny_dec`.

Currently
these functions are simply renamings of the functions
`crypto_kem_mceliece6960119_keypair`,
`crypto_kem_mceliece6960119_enc`,
and
`crypto_kem_mceliece6960119_dec`
from SUPERCOP.

### Building ciphertexts one block at a time

McTiny divides the Classic McEliece public key into blocks,
performs independent computations on each block,
and then assembles a ciphertext from the results of these computations.
The following functions help build ciphertexts in this way.

**Public-key structure.**
The public key communicates a matrix `H` of integers modulo 2.
The number of rows in the matrix is a system parameter `m*t`,
currently 1547.
This is the product of a system parameter `m`, currently 13,
and a system parameter `t`, currently 119.
The number of columns in the matrix is another system parameter `n`,
currently 6960.

The leftmost `m*t` columns in the matrix are always
an `m*t`-by-`m*t` identity matrix
and are not communicated explicitly.
The public key communicates the remaining `n-m*t` columns,
currently 5413 columns.
The public key consists of
the `n-m*t` bits at the end of the first row of the matrix
(in little-endian form, padded to a byte boundary),
then the `n-m*t` bits at the end of the second row of the matrix, etc.

**Extracting blocks from a public key.**
McTiny takes the columns of the public key `x` at a time,
where `x` is a McTiny parameter, currently 544.
Within each column, it takes the rows `y` at a time,
where `y` is another McTiny parameter, currently 16.
Each `y`-row-by-`x`-column portion of the public key is called a **block**.
The following function extracts one block from the public key,
starting at row number `y*rowpos` and column number `x*colpos`:

        #include "mctiny.h"

        unsigned char block[mctiny_BLOCKBYTES];
        const unsigned char pk[mctiny_PUBLICKEYBYTES];
        int rowpos;
        int colpos;

        mctiny_pk2block(block,pk,rowpos,colpos);

Here `rowpos` is allowed to be anything from `0` through `mctiny_ROWBLOCKS-1`,
and `colpos` is allowed to be anything from `0` through `mctiny_COLBLOCKS-1`.
A block can extend beyond the edges of the matrix
if `rowpos` is `mctiny_ROWBLOCKS-1`
or `colpos` is `mctiny_COLBLOCKS-1` (or both);
the corresponding output bits are set to 0.

Currently a block is represented as `xy` bits,
where the first `x` bits come from the first row of the block,
the next `x` bits come from the second row of the block,
etc.
(The parameter `x` is always a multiple of 8,
so there is no padding.)

**Error-vector structure.**
A Classic McEliece ciphertext is derived from a secret `n`-bit vector `e`.
This vector has weight `t`,
i.e., exactly `t` bits set.
Currently this means that `e` is a 6960-bit vector where exactly 119 bits are set.

**Generating error vectors.**
The McTiny server derives the vector `e` from a randomly chosen 32-byte `seed`
(`E` in the specification).
Rather than communicating the vector `e` to itself via a cookie,
the server communicates the more compact `seed` to itself via a cookie.

A randomly chosen 32-byte `seed`
is not necessarily valid:
i.e., it does not necessarily produce a vector `e`.
In this case the server tries another `seed`.
Here is the complete procedure to generate both `seed` and `e`:

        #include "mctiny.h"

        unsigned char seed[32];
        unsigned char e[mctiny_EBYTES];

        do
          randombytes(seed,sizeof seed);
        while (!mctiny_seedisvalid(seed));

        mctiny_seed2e(e,seed);

It would be possible to instead define all seeds as valid:
for example, `mctiny_seed2e`
could try deriving `e` from `seed`,
then try deriving `e` from a hash of `seed`,
then try deriving `e` from a hash of the hash of `seed`,
etc.
However,
the server would then have to compute the same hash chain again
to reconstruct `e` from a cookie.
Generating new seeds (as in the code above, or by repeatedly hashing an initial random seed)
means that each cookie uses just one `mctiny_seed2e` call.

It is also possible that a different internal definition of `mctiny_seed2e`
could generate `e` more efficiently,
perhaps also with a larger fraction of valid seeds.
The definition of `mctiny_seed2e` is not visible to the McTiny client,
so a server can substitute a different `mctiny_seed2e` definition
without affecting interoperability.
Implementors trying to replace `mctiny_seed2e` with something faster
should first understand the relevant
[security requirements](https://ntruprime.cr.yp.to/divergence-20180430.pdf).

**Ciphertext structure.**
A Classic McEliece ciphertext `c`
is a concatenation `c0+c1`.
The first part `c0` is `H` times `e`,
where `H` is the matrix communicated by the public key as above,
and `e` is the randomly chosen weight-`t` error vector described above.
This product `H*e` is called a **syndrome**.
The second part `c1` is the
[hash](hash.html)
of `2+e`,
where `2` means a string containing the single byte 2.
The corresponding session key is the hash
of `1+e+c`,
where `1` means a string containing the single byte 1.

Note that both of the hashes work conveniently with a single array that contains
a single byte,
then `e` (of length `mctiny_EBYTES`),
then `c` (of length `mctiny_CIPHERTEXTBYTES`).

**Handling a block.**
Given `e` and a block of `H`,
to compute the relevant `y`-bit contribution to the product `H*e`:

        #include "mctiny.h"

        unsigned char synd1[mctiny_YBYTES];
        const unsigned char e[mctiny_EBYTES];
        const unsigned char block[mctiny_BLOCKBYTES];
        int colpos;

        mctiny_eblock2syndrome(synd1,e,block,colpos);

You need to know the `colpos` used for the block
(between `0` and `mctiny_COLBLOCKS-1`);
this indicates which positions in `e` are relevant to the block.

**Merging `y`-bit results into `y*v`-bit pieces.**
The final product `H*e`
is assembled as a series of `y*v`-bit **pieces**.
Here `v` is another parameter, currently 5.
Here is how to compute all of these pieces:

        #include "mctiny.h"

        unsigned char synd2[mctiny_PIECES][mctiny_PIECEBYTES];
        unsigned char synd1[mctiny_YBYTES];
        unsigned char block[mctiny_BLOCKBYTES];
        const unsigned char pk[mctiny_PUBLICKEYBYTES];
        const unsigned char e[mctiny_EBYTES];
        int p;
        int i;
        int colpos;

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

`mctiny_pieceinit` copies the relevant
`y*v` bits of `e` to `synd2`.
In other words,
it handles the identity-matrix portion of the public matrix `H`.

`mctiny_pieceabsorb` xors the `y` bits from `synd1`
into the correct position in `synd2`.

**Merging `y*v`-bit pieces into a complete syndrome.**
Here is how to merge the pieces into
a single `m*t`-bit piece:

        #include "mctiny.h"

        unsigned char synd3[mctiny_COLBYTES];
        const unsigned char synd2[mctiny_PIECES][mctiny_PIECEBYTES];

        mctiny_mergepieces(synd3,synd2);

`mctiny_mergepieces`
concatenates the input bit strings,
stopping after `m*t` bits.

**Computing a ciphertext.**
Finally, here is how to compute
the corresponding ciphertext and session key:

        #include "mctiny.h"

        unsigned char c[mctiny_CIPHERTEXTBYTES];
        unsigned char k[mctiny_SESSIONKEYBYTES];
        const unsigned char synd3[mctiny_COLBYTES];
        const unsigned char e[mctiny_EBYTES];

        mctiny_finalize(c,k,synd3,e);

The resulting ciphertext can be decapsulated by `mctiny_dec`,
just like a ciphertext produced by `mctiny_enc`.
