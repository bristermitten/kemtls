{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- | Native bindings and wrappers for the MCTiny and McEliece KEM C libraries
module McTiny where

import Data.ByteString qualified as BS
import Data.ByteString.Internal
import Data.ByteString.Internal qualified as BS (create)
import Debug.Trace
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
ctBytes = 226

-- #PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES
ssBytes :: Int
ssBytes = 32

-- #packet_NONCEBYTES
packetNonceBytes :: Int
packetNonceBytes = 24

-- #mctiny_BLOCKBYTES
mctiny_BLOCKBYTES :: Int
mctiny_BLOCKBYTES = 1105

-- #define crypto_hash_shake256_BYTES 32
hashBytes :: Int
hashBytes = 32

-- int crypto_kem_mceliece6960119_keypair(unsigned char *pk, unsigned char *sk);
foreign import ccall safe "crypto_kem_mceliece6960119_keypair"
  c_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_kem_mceliece6960119_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
foreign import ccall safe "crypto_kem_mceliece6960119_enc"
  c_enc :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_kem_mceliece6960119_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
foreign import ccall safe "crypto_kem_mceliece6960119_dec"
  c_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- void mctiny_pk2block(unsigned char *out,const unsigned char *pk,int rowpos,int colpos)
foreign import ccall safe "mctiny_pk2block"
  c_pk2block :: Ptr Word8 -> Ptr Word8 -> CInt -> CInt -> IO ()

-- int crypto_stream_xsalsa20_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
foreign import ccall unsafe "bridge_crypto_stream_xsalsa20_xor"
  cs_xsalsa20_xor :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_onetimeauth_poly1305(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *)
foreign import ccall safe "bridge_crypto_onetimeauth_poly1305"
  cs_poly1305 :: Ptr Word8 -> Ptr Word8 -> CULLong -> Ptr Word8 -> IO CInt

-- int crypto_hash_shake256(unsigned char *out, const unsigned char *in, unsigned long long inlen)
foreign import ccall safe "crypto_hash_shake256"
  cs_shake256 :: Ptr Word8 -> Ptr Word8 -> CULLong -> IO CInt

-- | Generate a McEliece keypair
generateKeypair :: IO McElieceKeypair
generateKeypair = do
  pkFPtr <- mallocForeignPtrBytes pkBytes
  skFPtr <- mallocForeignPtrBytes skBytes

  withForeignPtr pkFPtr $ \pkPtr ->
    withForeignPtr skFPtr $ \skPtr -> do
      res <- c_keypair pkPtr skPtr
      when (res /= 0) $ error "McEliece KeyGen failed!"

  pure $ McElieceKeypair (McEliecePublicKey pkFPtr) (McElieceSecretKey skFPtr)

-- | Encapsulate a shared secret using the given public key
encapsulate :: McEliecePublicKey -> IO (Ciphertext, SharedSecret)
encapsulate (McEliecePublicKey pkFPtr) = do
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

-- | Decapsulate a shared secret using the given secret key and ciphertext
decap :: McElieceSecretKey -> Ciphertext -> IO SharedSecret
decap (McElieceSecretKey skFPtr) ct = do
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
  , secretKey :: McElieceSecretKey
  }
  deriving stock (Eq, Show)

data McElieceEncapsulation = McElieceEncapsulation
  { ciphertext :: BS.ByteString
  , sharedSecret :: BS.ByteString
  }
  deriving stock (Eq, Show)

-- | A pointer to a McEliece secret key
newtype McElieceSecretKey = McElieceSecretKey (ForeignPtr Word8) deriving stock (Eq, Show)

type Ciphertext = BS.ByteString
type SharedSecret = BS.ByteString

{-
void packet_encrypt(const unsigned char *n,const unsigned char *k)
{
  if (packetformat != 1) invalid();
  if (!packetformat) return;
  packetformat = 2;
  crypto_stream_xsalsa20_xor(packet,packet,packetpos,n,k);
  crypto_onetimeauth_poly1305(packet+16,packet+32,packetpos-32,packet);
  memset(packet,0,16);
}
-}

{- | Encrypt packet data using XSalsa20 and Poly1305
The data does not have to be the full packet, just part of the data

Produces a bytestring of length (16 + payload length)

nicer version of the packet_encrypt function in packet.c
-}
encryptPacketData :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
encryptPacketData payloadBS nonceBS keyBS = do
  -- Sanity Checks
  when (BS.length nonceBS /= packetNonceBytes) $ error "Nonce must be 24 bytes"
  when (BS.length keyBS /= hashBytes) $ error "Key must be 32 bytes"

  let payloadLen = BS.length payloadBS
      totalLen = 32 + payloadLen

  -- Allocate the full output buffer (Header + Payload)
  fullBuffer <- BS.create totalLen $ \bufPtr -> do
    -- zero the first 32 bytes
    fillBytes bufPtr 32 0

    -- copy payload
    BS.useAsCStringLen payloadBS $ \(payloadPtr, copyLen) ->
      copyBytes (bufPtr `plusPtr` 32) (castPtr payloadPtr) copyLen

    -- call xsalsa20_xor
    BS.useAsCString nonceBS $ \tempNoncePtr -> do
      BS.useAsCString keyBS $ \tempKeyPtr -> do
        -- Call C function with the safe temp pointers
        res <-
          cs_xsalsa20_xor
            bufPtr -- output
            bufPtr -- input
            (fromIntegral totalLen) -- length
            (castPtr tempNoncePtr) -- nonce
            (castPtr tempKeyPtr) -- key
        when (res /= 0) $ error "XSalsa20 Failed"

    -- authenticate with poly1305
    res <-
      cs_poly1305
        (bufPtr `plusPtr` 16) -- output MAC location
        (bufPtr `plusPtr` 32) -- input
        (fromIntegral payloadLen) -- input length
        bufPtr -- key ptr
    when (res /= 0) $ error "Poly1305 Failed"

  -- drop the first 16 bytes which should be useless
  return $ BS.drop 16 fullBuffer

{-
int packet_decrypt(const unsigned char *n,const unsigned char *k)
{
  unsigned char subkey[32];
  if (packetformat != 2) invalid();
  if (!packetformat) return -1;
  packetformat = 1;
  crypto_stream_xsalsa20(subkey,32,n,k);
  if (crypto_onetimeauth_poly1305_verify(packet+16,packet+32,packetpos-32,subkey) != 0) {
    invalid();
    return -1;
  }
  crypto_stream_xsalsa20_xor(packet,packet,packetpos,n,k);
  memset(packet,0,32);
  return 0;
}
-}
decryptPacketData :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
decryptPacketData encryptedBS nonceBS keyBS = do
  -- Sanity Checks
  when (BS.length nonceBS /= packetNonceBytes) $ error "Nonce must be 24 bytes"
  when (BS.length keyBS /= hashBytes) $ error "Key must be 32 bytes"
  when (BS.length encryptedBS < 16) $ error "Encrypted data too short"

  let (cipherTag, ciphertext) = BS.splitAt 16 encryptedBS
      ctLen = BS.length ciphertext
      totalLen = 32 + ctLen -- 32 bytes headroom + Ciphertext length
  fullBuffer <- BS.create totalLen $ \bufPtr -> do
    -- zero the header
    fillBytes bufPtr 32 0

    -- copy ciphertext to offset 32
    BS.useAsCStringLen ciphertext $ \(ctPtr, len) ->
      copyBytes (bufPtr `plusPtr` 32) (castPtr ctPtr) len

    -- call xsalsa20_xor to generate the subkey and decrypt
    BS.useAsCString nonceBS $ \noncePtr -> do
      BS.useAsCString keyBS $ \keyPtr -> do
        salsaRes <-
          cs_xsalsa20_xor
            bufPtr -- output
            bufPtr -- input
            32 -- length
            (castPtr noncePtr) -- nonce
            (castPtr keyPtr) -- key
        when (salsaRes /= 0) $ error "XSalsa20 Failed"

        allocaBytes 16 $ \computedTagPtr -> do
          polyRes <-
            cs_poly1305
              computedTagPtr -- output
              (bufPtr `plusPtr` 32) -- input
              (fromIntegral ctLen) -- input length
              bufPtr -- key ptr
          when (polyRes /= 0) $ error "Poly1305 Failed"

          -- compare computed tag with provided tag
          BS.useAsCStringLen cipherTag $ \(tagPtr, tagLen) -> do
            tagMatch <- memcmp computedTagPtr (castPtr tagPtr) (fromIntegral tagLen)
            when (tagMatch /= 0) $ error "Authentication failed: tags do not match"

        -- decrypt the ciphertext
        decryptRes <-
          cs_xsalsa20_xor
            bufPtr -- output
            bufPtr -- input
            (fromIntegral totalLen) -- length
            (castPtr noncePtr) -- nonce
            (castPtr keyPtr) -- key
        when (decryptRes /= 0) $ error "XSalsa20 Decryption Failed"

  -- drop the first 32 bytes
  return $ BS.drop 32 fullBuffer

mctinyHash :: BS.ByteString -> IO BS.ByteString
mctinyHash inputBS = do
  let inputLen = fromIntegral (BS.length inputBS) :: CULLong
  let outputLen = fromIntegral hashBytes :: CULLong
  BS.create (fromIntegral outputLen) $ \outputPtr ->
    BS.useAsCString inputBS $ \inputPtr -> do
      res <- cs_shake256 outputPtr (castPtr inputPtr) inputLen
      when (res /= 0) $ error "Hashing failed"

-- | A pointer to a McEliece public key
newtype McEliecePublicKey = McEliecePublicKey (ForeignPtr Word8) deriving stock (Eq, Show)

readPublicKey :: FilePath -> IO McEliecePublicKey
readPublicKey path = do
  bs <- readFileBS path
  when (BS.length bs /= pkBytes) $
    error $
      "Public key file has incorrect length: expected " <> show pkBytes <> ", got " <> show (BS.length bs)
  pkPtr <- mallocForeignPtrBytes pkBytes
  withForeignPtr pkPtr $ \ptr ->
    BS.useAsCString bs $ \bsPtr ->
      copyBytes ptr (castPtr bsPtr) pkBytes
  pure (McEliecePublicKey pkPtr)

readSecretKey :: FilePath -> IO McElieceSecretKey
readSecretKey path = do
  bs <- readFileBS path
  when (BS.length bs /= skBytes) $
    error $
      "Secret key file has incorrect length: expected " <> show skBytes <> ", got " <> show (BS.length bs)
  skPtr <- mallocForeignPtrBytes skBytes
  withForeignPtr skPtr $ \ptr ->
    BS.useAsCString bs $ \bsPtr ->
      copyBytes ptr (castPtr bsPtr) skBytes
  pure (McElieceSecretKey skPtr)

publicKeyBytes :: McEliecePublicKey -> IO BS.ByteString
publicKeyBytes (McEliecePublicKey fptr) = BS.create pkBytes $ \ptr ->
  withForeignPtr fptr $ \pkPtr ->
    copyBytes ptr pkPtr pkBytes
