{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module McTiny where

import Foreign
import Foreign.C.Types

-- #crypto_kem_mceliece6960119_PUBLICKEYBYTES
pkBytes :: Int
pkBytes = 1047319

-- #crypto_kem_mceliece6960119_SECRETKEYBYTES
skBytes :: Int
skBytes = 13948

-- int crypto_kem_mceliece6960119_keypair(unsigned char *pk, unsigned char *sk);
foreign import ccall safe "crypto_kem_mceliece6960119_keypair"
  c_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

generateKeypair :: IO (ForeignPtr Word8, ForeignPtr Word8)
generateKeypair = do
  -- Allocate 1MB for PK on the Heap (Pinned)
  pkFPtr <- mallocForeignPtrBytes pkBytes
  skFPtr <- mallocForeignPtrBytes skBytes

  withForeignPtr pkFPtr $ \pkPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      res <- c_keypair pkPtr skPtr
      when (res /= 0) $ error "McEliece KeyGen failed!"

  return (pkFPtr, skFPtr)
