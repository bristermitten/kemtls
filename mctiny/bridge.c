#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "math/mceliece/operations.h"
#include "math/mceliece/api.h"
#include "math/common/fips202.h"
#include "tweetnacl.h"

// 1. Bridge for Classic McEliece 6960119
// We map the McTiny function names to the PQClean implementation

int crypto_kem_mceliece6960119_keypair(unsigned char *pk, unsigned char *sk)
{
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
}

int crypto_kem_mceliece6960119_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int crypto_kem_mceliece6960119_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss, ct, sk);
}

// 2. Bridge for SHA3 / Keccak (Used by McTiny internally)
// McTiny uses a specific API style for Keccak that we need to satisfy

void Keccak_HashInstance(void *instance)
{
    // McTiny might define instance differently, but for standard FIPS202
    // we just need the shake256 context.
    // Note: This is a simplification. If McTiny accesses struct members directly,
    // we might need to map the struct.
    // For now, we assume standard usage.
    printf("Keccak_HashInstance called - not implemented\n");
    exit(1);
}

// 3. Real Randombytes (Using /dev/urandom)
// This makes the keys actually random and secure.
void randombytes(unsigned char *x, unsigned long long xlen)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        abort();
    fread(x, 1, xlen, f);
    fclose(f);
}

int crypto_hash_shake256(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    shake256(out, 32, in, inlen);
    return 0;
}


// since `crypto_stream_xsalsa20_xor` is defined as a macro
// the haskell FFI cant bind to it directly
// so we define this alias (very stupid)
int bridge_crypto_stream_xsalsa20_xor(unsigned char *c,const unsigned char *m,unsigned long long mlen,const unsigned char *n,const unsigned char *k)
{
    return crypto_stream_xsalsa20_xor(c, m, mlen, n, k);
}

// ditto
int bridge_crypto_onetimeauth_poly1305(unsigned char *out,const unsigned char *in,unsigned long long inlen,const unsigned char *k)
{
    return crypto_onetimeauth_poly1305(out, in, inlen, k);
}

// Helper comparator for qsort
int int32_cmp(const void *a, const void *b)
{
    int32_t ia = *(const int32_t *)a;
    int32_t ib = *(const int32_t *)b;
    if (ia < ib)
        return -1;
    if (ia > ib)
        return 1;
    return 0;
}

// The function McTiny expects
void crypto_sort_int32(int32_t *x, long long n)
{
    qsort(x, n, sizeof(int32_t), int32_cmp);
}