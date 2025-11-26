{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module McTiny where

import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BS (create)
import Foreign
import Foreign.C.Types

-- #crypto_kem_mceliece6960119_PUBLICKEYBYTES
pkBytes :: Int
pkBytes = 1047319

-- #crypto_kem_mceliece6960119_SECRETKEYBYTES
skBytes :: Int
skBytes = 13948

-- #crypto_kem_mceliece6960119_CIPHERTEXTBYTES
ctBytes :: Int
ctBytes = 194

-- #PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES
ssBytes :: Int
ssBytes = 32

-- int crypto_kem_mceliece6960119_keypair(unsigned char *pk, unsigned char *sk);
foreign import ccall safe "crypto_kem_mceliece6960119_keypair"
  c_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_kem_mceliece6960119_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
foreign import ccall safe "crypto_kem_mceliece6960119_enc"
  c_enc :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_kem_mceliece6960119_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
foreign import ccall safe "crypto_kem_mceliece6960119_dec"
  c_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

generateKeypair :: IO McElieceKeypair
generateKeypair = do
  pkFPtr <- mallocForeignPtrBytes pkBytes
  skFPtr <- mallocForeignPtrBytes skBytes

  withForeignPtr pkFPtr $ \pkPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      res <- c_keypair pkPtr skPtr
      when (res /= 0) $ error "McEliece KeyGen failed!"

  pure $ McElieceKeypair pkFPtr skFPtr

encapsulate :: McEliecePublicKey -> IO (BS.ByteString, BS.ByteString)
encapsulate pkFPtr = do
  ctFPtr <- mallocForeignPtrBytes ctBytes
  ssFPtr <- mallocForeignPtrBytes ssBytes

  withForeignPtr pkFPtr $ \pkPtr ->
    withForeignPtr ctFPtr $ \ctPtr ->
      withForeignPtr ssFPtr $ \ssPtr -> do
        res <- c_enc ctPtr ssPtr pkPtr
        when (res /= 0) $ error "McEliece Encapsulation failed!"

        ct <- BS.create ctBytes $ \destPtr ->
          copyBytes destPtr ctPtr (fromIntegral ctBytes)

        ss <- BS.create ssBytes $ \destPtr ->
          copyBytes destPtr ssPtr (fromIntegral ssBytes)
        return (ct, ss)

decap :: McElieceSecretKey -> BS.ByteString -> IO BS.ByteString
decap skFPtr ct = do
  ssFPtr <- mallocForeignPtrBytes ssBytes
  withForeignPtr skFPtr $ \skPtr ->
    BS.useAsCString ct $ \ctPtr ->
      withForeignPtr ssFPtr $ \ssPtr -> do
        res <- c_dec ssPtr (castPtr ctPtr) skPtr
        when (res /= 0) $ error "Decapsulation failed"

        BS.create ssBytes $ \destPtr ->
          copyBytes destPtr ssPtr (fromIntegral ssBytes)

data McElieceKeypair = McElieceKeypair
  { publicKey :: McEliecePublicKey
  , secretKey :: ForeignPtr Word8
  }
  deriving stock (Eq, Show)

data McElieceEncapsulation = McElieceEncapsulation
  { ciphertext :: BS.ByteString
  , sharedSecret :: BS.ByteString
  }
  deriving stock (Eq, Show)

type McEliecePublicKey = ForeignPtr Word8
type McElieceSecretKey = ForeignPtr Word8
