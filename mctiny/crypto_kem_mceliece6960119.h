#ifndef CRYPTO_KEM_MCELIECE6960119_H
#define CRYPTO_KEM_MCELIECE6960119_H

#include "math/mceliece/api.h"

// Map the PQClean constants to what McTiny expects
#define crypto_kem_mceliece6960119_PUBLICKEYBYTES PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES
#define crypto_kem_mceliece6960119_SECRETKEYBYTES PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES

// Note: McTiny expects the ciphertext to be larger by 32 bytes
// In the actual supercop implementation this is defined as 226
// but in PQClean it is 194, so we add 32 here.
// I think this is because the kem ciphertext is concatenated with a hash or something.
#define crypto_kem_mceliece6960119_CIPHERTEXTBYTES (PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES + 32)
#define crypto_kem_mceliece6960119_BYTES PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES

// Prototypes
int crypto_kem_mceliece6960119_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_mceliece6960119_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_mceliece6960119_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif