{-# LANGUAGE CPP #-}

module Constants where

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

#define cookie_c0_Bytes 81
cookieC0Bytes :: (Num a) => a
cookieC0Bytes = cookie_c0_Bytes

type CookieC0Bytes :: Nat
type CookieC0Bytes = cookie_c0_Bytes

#define packet_ExtensionsBytes 512
packetExtensionsBytes :: (Num a) => a
packetExtensionsBytes = packet_ExtensionsBytes

type PacketExtensionsBytes :: Nat
type PacketExtensionsBytes = packet_ExtensionsBytes

#define mcTiny_params_l 8
-- mctiny_COLBLOCKS
-- i.e. how many columns in the McTiny matrix
mcTinyL :: (Num a) => a
mcTinyL = mcTiny_params_l

type McTinyL :: Nat
type McTinyL = mcTiny_params_l

#define mcTiny_params_r 119
-- mctiny_ROWBLOCKS
-- i.e. how many rows in the McTiny matrix
mcTinyR :: (Num a) => a
mcTinyR = mcTiny_params_r

type McTinyR :: Nat
type McTinyR = mcTiny_params_r
