{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- | Native bindings and wrappers for the MCTiny and McEliece KEM C libraries
module McTiny where

import Constants
import Data.ByteString qualified as BS
import Data.ByteString.Internal
import Data.ByteString.Internal qualified as BS (create)
import Foreign
import Foreign.C.Types
import GHC.TypeLits (type (+), type (-))
import SizedByteString (SizedByteString, SizedString (..), mkSized, mkSizedOrError, randomSized, sizedLength)
import SizedByteString qualified as SizedBS

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

-- void mctiny_pk2block(unsigned char *out,const unsigned char *pk,int rowpos,int colpos)
foreign import ccall safe "mctiny_pk2block"
    c_mctiny_pk2block :: Ptr Word8 -> Ptr Word8 -> CInt -> CInt -> IO ()

-- void mctiny_seed2e(unsigned char *e,const unsigned char *seed)
foreign import ccall safe "mctiny_seed2e"
    c_mctiny_seed2e :: Ptr Word8 -> Ptr Word8 -> IO ()

-- void mctiny_eblock2syndrome(unsigned char *s,const unsigned char *e,const unsigned char *block,int colpos)
foreign import ccall safe "mctiny_eblock2syndrome"
    c_mctiny_eblock2syndrome :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> CInt -> IO ()

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
    ctFPtr <- mallocForeignPtrBytes ciphertextBytes
    ssFPtr <- mallocForeignPtrBytes sharedSecretBytes

    withForeignPtr pkFPtr $ \pkPtr ->
        withForeignPtr ctFPtr $ \ctPtr ->
            withForeignPtr ssFPtr $ \ssPtr -> do
                res <- c_enc ctPtr ssPtr pkPtr
                when (res /= 0) $ error "McEliece Encapsulation failed!"

                ct <- BS.create ciphertextBytes $ \destPtr ->
                    copyBytes destPtr ctPtr (fromIntegral ciphertextBytes)

                ss <- BS.create sharedSecretBytes $ \destPtr ->
                    copyBytes destPtr ssPtr (fromIntegral sharedSecretBytes)
                return (mkSizedOrError ct, mkSizedOrError ss)

-- | Decapsulate a shared secret using the given secret key and ciphertext
decap :: McElieceSecretKey -> Ciphertext -> IO SharedSecret
decap (McElieceSecretKey skFPtr) ct = do
    ssFPtr <- mallocForeignPtrBytes sharedSecretBytes
    withForeignPtr skFPtr $ \skPtr ->
        BS.useAsCString (fromSized ct) $ \ctPtr ->
            withForeignPtr ssFPtr $ \ssPtr -> do
                res <- c_dec ssPtr (castPtr ctPtr) skPtr
                when (res /= 0) $ error "Decapsulation failed"

                mkSizedOrError
                    <$> BS.create
                        sharedSecretBytes
                        ( \destPtr ->
                            copyBytes destPtr ssPtr (fromIntegral sharedSecretBytes)
                        )

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

type Ciphertext = SizedByteString CiphertextBytes
type SharedSecret = SizedByteString SharedSecretBytes

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

{- | Encrypt and authenticate packet data using XSalsa20 and Poly1305
The data does not have to be the full packet, just part of the data

Produces a bytestring of length (16 + payload length)

nicer version of the packet_encrypt function in packet.c
-}
encryptPacketData ::
    (KnownNat payloadLen, KnownNat (payloadLen + 16)) =>
    SizedByteString payloadLen ->
    SizedByteString PacketNonceBytes ->
    SizedByteString HashBytes ->
    IO (SizedByteString (payloadLen + 16))
encryptPacketData payloadBS nonceBS keyBS = do
    let payloadLen = sizedLength payloadBS
        totalLen = hashBytes + payloadLen

    -- Allocate the full output buffer (Header + Payload)
    fullBuffer <- BS.create totalLen $ \bufPtr -> do
        -- zero the first 32 bytes
        fillBytes bufPtr hashBytes 0

        -- copy payload
        BS.useAsCStringLen (fromSized payloadBS) $ \(payloadPtr, copyLen) ->
            copyBytes (bufPtr `plusPtr` hashBytes) (castPtr payloadPtr) copyLen
        -- call xsalsa20_xor
        BS.useAsCString (fromSized nonceBS) $ \tempNoncePtr -> do
            BS.useAsCString (fromSized keyBS) $ \tempKeyPtr -> do
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
    return $ mkSizedOrError (BS.drop 16 fullBuffer)

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
decryptPacketData ::
    (HasCallStack, KnownNat payloadLen) =>
    SizedByteString (16 + payloadLen) ->
    SizedByteString PacketNonceBytes ->
    SizedByteString HashBytes ->
    IO (SizedByteString payloadLen)
decryptPacketData encryptedBS nonceBS keyBS = do
    -- Sanity Checks

    let (cipherTag, ciphertext) = BS.splitAt 16 (fromSized encryptedBS)
        ctLen = BS.length ciphertext
        totalLen = 32 + ctLen -- 32 bytes headroom + Ciphertext length
    fullBuffer <- BS.create totalLen $ \bufPtr -> do
        -- zero the header
        fillBytes bufPtr 32 0

        -- copy ciphertext to offset 32
        BS.useAsCStringLen ciphertext $ \(ctPtr, len) ->
            copyBytes (bufPtr `plusPtr` 32) (castPtr ctPtr) len

        -- call xsalsa20_xor to generate the subkey and decrypt
        BS.useAsCString (fromSized nonceBS) \noncePtr -> do
            BS.useAsCString (fromSized keyBS) \keyPtr -> do
                salsaRes <-
                    cs_xsalsa20_xor
                        bufPtr -- output
                        bufPtr -- input
                        32 -- length
                        (castPtr noncePtr) -- nonce
                        (castPtr keyPtr) -- key
                when (salsaRes /= 0) $ error "XSalsa20 Failed"

                allocaBytes 16 \computedTagPtr -> do
                    polyRes <-
                        cs_poly1305
                            computedTagPtr -- output
                            (bufPtr `plusPtr` 32) -- input
                            (fromIntegral ctLen) -- input length
                            bufPtr -- key ptr
                    when (polyRes /= 0) $ error "Poly1305 Failed"

                    -- compare computed tag with provided tag
                    BS.useAsCStringLen cipherTag \(tagPtr, tagLen) -> do
                        tagMatch <- memcmp computedTagPtr (castPtr tagPtr) (fromIntegral tagLen)
                        when (tagMatch /= 0) $ do
                            expected <- BS.packCStringLen (tagPtr, tagLen)
                            actual <- BS.packCStringLen (castPtr computedTagPtr, tagLen)
                            error $
                                "Authentication failed: tags do not match."
                                    <> " Computed tag: "
                                    <> show expected
                                    <> " Provided tag: "
                                    <> show actual

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
    return $ mkSizedOrError (BS.drop 32 fullBuffer)

mctinyHash :: BS.ByteString -> IO (SizedByteString HashBytes)
mctinyHash inputBS = do
    let inputLen = fromIntegral (BS.length inputBS) :: CULLong
    let outputLen = hashBytes :: CULLong
    res <- BS.create (fromIntegral outputLen) \outputPtr ->
        BS.useAsCString inputBS \inputPtr -> do
            res <- cs_shake256 outputPtr (castPtr inputPtr) inputLen
            when (res /= 0) $ error "Hashing failed"
    case mkSized res of
        Just sizedRes -> return sizedRes
        Nothing -> error "Hash output has incorrect length"

-- | A pointer to a McEliece public key
newtype McEliecePublicKey = McEliecePublicKey (ForeignPtr Word8) deriving stock (Eq, Show)

readPublicKey :: FilePath -> IO McEliecePublicKey
readPublicKey path = do
    bs <- readFileBS path
    when (BS.length bs /= pkBytes) $
        error $
            "Public key file has incorrect length: expected " <> show pkBytes <> ", got " <> show (BS.length bs)
    pkPtr <- mallocForeignPtrBytes pkBytes
    withForeignPtr pkPtr \ptr ->
        BS.useAsCString bs \bsPtr ->
            copyBytes ptr (castPtr bsPtr) pkBytes
    pure (McEliecePublicKey pkPtr)

readSecretKey :: FilePath -> IO McElieceSecretKey
readSecretKey path = do
    bs <- readFileBS path
    when (BS.length bs /= skBytes) $
        error $
            "Secret key file has incorrect length: expected " <> show skBytes <> ", got " <> show (BS.length bs)
    skPtr <- mallocForeignPtrBytes skBytes

    withForeignPtr skPtr \ptr ->
        BS.useAsCString bs \bsPtr ->
            copyBytes ptr (castPtr bsPtr) skBytes
    pure (McElieceSecretKey skPtr)

publicKeyBytes :: McEliecePublicKey -> IO BS.ByteString
publicKeyBytes (McEliecePublicKey fptr) = BS.create pkBytes $ \ptr ->
    withForeignPtr fptr $ \pkPtr ->
        copyBytes ptr pkPtr pkBytes

pk2Block ::
    McEliecePublicKey ->
    Int -> -- rowPos
    Int -> -- colPos
    IO (SizedByteString McTinyBlockBytes)
pk2Block (McEliecePublicKey pkFPtr) rowPos colPos = do
    blockBS <- BS.create mctinyBlockBytes $ \outPtr ->
        withForeignPtr pkFPtr $ \pkPtr -> do
            c_mctiny_pk2block outPtr pkPtr (fromIntegral rowPos) (fromIntegral colPos)
    return $ mkSizedOrError blockBS

seedToE ::
    SizedByteString CookieSeedBytes ->
    IO (SizedByteString McTinyErrorVectorBytes)
seedToE seedBS = do
    eBS <- BS.create mctinyErrorVectorBytes $ \ePtr ->
        BS.useAsCString (fromSized seedBS) $ \seedPtr -> do
            c_mctiny_seed2e ePtr (castPtr seedPtr)
    return $ mkSizedOrError eBS

eBlockToSyndrome ::
    SizedByteString McTinyErrorVectorBytes ->
    SizedByteString McTinyBlockBytes ->
    Int -> -- colPos
    IO (SizedByteString McTinySyndromeBytes)
eBlockToSyndrome eBS blockBS colPos = do
    sBS <- BS.create mctinySyndromeBytes $ \sPtr ->
        BS.useAsCString (fromSized eBS) \ePtr ->
            BS.useAsCString (fromSized blockBS) \blockPtr -> do
                c_mctiny_eblock2syndrome
                    sPtr
                    (castPtr ePtr)
                    (castPtr blockPtr)
                    (fromIntegral colPos)
    return $ mkSizedOrError sBS

computePartialSyndrome ::
    SizedByteString CookieSeedBytes ->
    SizedByteString McTinyBlockBytes ->
    Int -> -- colPos
    IO (SizedByteString McTinySyndromeBytes)
computePartialSyndrome seedBS blockBS colPos = do
    eBS <- seedToE seedBS
    eBlockToSyndrome eBS blockBS colPos
