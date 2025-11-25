/* crypto_hash_shake256.h */
#ifndef CRYPTO_HASH_SHAKE256_H
#define CRYPTO_HASH_SHAKE256_H

#define crypto_hash_shake256_BYTES 32

// Standard Supercop API: Fixed 32-byte output for "hash" calls
int crypto_hash_shake256(unsigned char *out, const unsigned char *in, unsigned long long inlen);

#endif