{-# LANGUAGE CPP #-}

module Constants where

import GHC.TypeLits (type (+))

-- #crypto_kem_mceliece6960119_PUBLICKEYBYTES
#define public_key_bytes 1047319
pkBytes :: Int
pkBytes = public_key_bytes

-- #crypto_kem_mceliece6960119_SECRETKEYBYTES
#define secret_key_bytes 13948
skBytes :: Int
skBytes = secret_key_bytes

-- #crypto_kem_mceliece6960119_CIPHERTEXTBYTES
#define ciphertext_bytes 226    
ciphertextBytes :: Int
ciphertextBytes = ciphertext_bytes

type CiphertextBytes :: Nat
type CiphertextBytes = ciphertext_bytes

-- #PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES
#define shared_secret_bytes 32
sharedSecretBytes :: Int
sharedSecretBytes = shared_secret_bytes

type SharedSecretBytes :: Nat
type SharedSecretBytes = shared_secret_bytes

-- #packet_NONCEBYTES
#define packet_NONCEBYTES 24
packetNonceBytes :: (Num a) => a
packetNonceBytes = packet_NONCEBYTES

type PacketNonceBytes :: Nat
type PacketNonceBytes = packet_NONCEBYTES

-- #mctiny_BLOCKBYTES
#define mctiny_BLOCKBYTES 1105
mctinyBlockBytes :: (Num a) => a
mctinyBlockBytes = mctiny_BLOCKBYTES

type McTinyBlockBytes :: Nat
type McTinyBlockBytes = mctiny_BLOCKBYTES

#define crypto_hash_shake256_BYTES 32
hashBytes :: (Num a) => a
hashBytes = crypto_hash_shake256_BYTES

type HashBytes :: Nat
type HashBytes = crypto_hash_shake256_BYTES

#define nonce_randomPartBytes 22
-- 176 / 8 = 22
nonceRandomPartBytes :: (Num a) => a
nonceRandomPartBytes = nonce_randomPartBytes

type NonceRandomPartBytes :: Nat
type NonceRandomPartBytes = nonce_randomPartBytes

#define cookie_SecretKeyBytes 32
cookieSecretKeyBytes :: (Num a) => a
cookieSecretKeyBytes = cookie_SecretKeyBytes

type CookieSecretKeyBytes :: Nat
type CookieSecretKeyBytes = cookie_SecretKeyBytes

#define cookie_seedBytes 32
cookieSeedBytes :: (Num a) => a
cookieSeedBytes = cookie_seedBytes

type CookieSeedBytes :: Nat
type CookieSeedBytes = cookie_seedBytes

#define mctiny_COOKIE0BYTES 81
cookieC0Bytes :: (Num a) => a
cookieC0Bytes = mctiny_COOKIE0BYTES

type CookieC0Bytes :: Nat
type CookieC0Bytes = mctiny_COOKIE0BYTES

#define mctiny_COOKIEBLOCKBYTES 19
cookie1BlockBytes :: (Num a) => a
cookie1BlockBytes = mctiny_COOKIEBLOCKBYTES

type Cookie1BlockBytes :: Nat
type Cookie1BlockBytes = mctiny_COOKIEBLOCKBYTES

#define packet_ExtensionsBytes 512
packetExtensionsBytes :: (Num a) => a
packetExtensionsBytes = packet_ExtensionsBytes

type PacketExtensionsBytes :: Nat
type PacketExtensionsBytes = packet_ExtensionsBytes

#define mcTiny_params_l 8
-- mctiny_COLBLOCKS
-- i.e. how many columns in the McTiny matrix
mcTinyColBlocks :: (Num a) => a
mcTinyColBlocks = mcTiny_params_l

type McTinyColBlocks :: Nat
type McTinyColBlocks = mcTiny_params_l

#define mcTiny_params_r 119
-- mctiny_ROWBLOCKS
-- i.e. how many rows in the McTiny matrix
mcTinyRowBlocks :: (Num a) => a
mcTinyRowBlocks = mcTiny_params_r

type McTinyRowBlocks :: Nat
type McTinyRowBlocks = mcTiny_params_r

#define mcTiny_encryption_headerBytes 16
mcTinyEncryptionHeaderBytes :: (Num a) => a
mcTinyEncryptionHeaderBytes = mcTiny_encryption_headerBytes

type McTinyEncryptionHeaderBytes :: Nat
type McTinyEncryptionHeaderBytes = mcTiny_encryption_headerBytes

type EncryptedSize n = n + McTinyEncryptionHeaderBytes

#define mctiny_EBYTES 870
mctinyErrorVectorBytes :: (Num a) => a
mctinyErrorVectorBytes = mctiny_EBYTES

type McTinyErrorVectorBytes :: Nat
type McTinyErrorVectorBytes = mctiny_EBYTES

#define mctiny_YBYTES 2
mctinySyndromeBytes :: (Num a) => a
mctinySyndromeBytes = mctiny_YBYTES

type McTinySyndromeBytes :: Nat
type McTinySyndromeBytes = mctiny_YBYTES

#define mctiny_V 7
mctinyV :: (Num a) => a
mctinyV = mctiny_V

type McTinyV :: Nat
type McTinyV = mctiny_V
