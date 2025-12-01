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
import GHC.TypeLits (type (+), type (-), type (<=))
import Nonce (Nonce, fullNonce)
import SizedByteString (SizedByteString, SizedString (..), sizedLength)
import SizedByteString qualified as SizedBS

-- int crypto_kem_mceliece6960119_keypair(unsigned char *pk, unsigned char *sk);
foreign import ccall unsafe "crypto_kem_mceliece6960119_keypair"
    c_keypair :: Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_kem_mceliece6960119_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
foreign import ccall safe "crypto_kem_mceliece6960119_enc"
    c_enc :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

-- int crypto_kem_mceliece6960119_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
foreign import ccall safe "crypto_kem_mceliece6960119_dec"
    c_dec :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt

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

-- int mctiny_seedisvalid(const unsigned char *seed)
foreign import ccall safe "mctiny_seedisvalid"
    c_mctiny_seedisvalid :: Ptr Word8 -> IO CInt

-- void mctiny_seed2e(unsigned char *e,const unsigned char *seed)
foreign import ccall safe "mctiny_seed2e"
    c_mctiny_seed2e :: Ptr Word8 -> Ptr Word8 -> IO ()

-- void mctiny_eblock2syndrome(unsigned char *s,const unsigned char *e,const unsigned char *block,int colpos)
foreign import ccall safe "mctiny_eblock2syndrome"
    c_mctiny_eblock2syndrome :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> CInt -> IO ()

-- void mctiny_pieceinit(unsigned char *synd2,const unsigned char *e,int p)
foreign import ccall safe "mctiny_pieceinit"
    c_mctiny_pieceinit :: Ptr Word8 -> Ptr Word8 -> CInt -> IO ()

-- void mctiny_pieceabsorb(unsigned char *synd2,const unsigned char *synd1,int i)
foreign import ccall safe "mctiny_pieceabsorb"
    c_mctiny_pieceabsorb :: Ptr Word8 -> Ptr Word8 -> CInt -> IO ()

-- void mctiny_mergepieces(unsigned char *synd3,const unsigned char (*synd2)[mctiny_PIECEBYTES])
foreign import ccall safe "mctiny_mergepieces"
    c_mctiny_mergepieces :: Ptr Word8 -> Ptr Word8 -> IO ()

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

                ct <- SizedBS.create @CiphertextBytes $ \destPtr ->
                    copyBytes destPtr ctPtr (fromIntegral ciphertextBytes)

                ss <- SizedBS.create @SharedSecretBytes $ \destPtr ->
                    copyBytes destPtr ssPtr (fromIntegral sharedSecretBytes)
                return (ct, ss)

-- | Decapsulate a shared secret using the given secret key and ciphertext
decap :: (HasCallStack) => McElieceSecretKey -> Ciphertext -> IO SharedSecret
decap (McElieceSecretKey skFPtr) ct = do
    ssFPtr <- mallocForeignPtrBytes sharedSecretBytes
    withForeignPtr skFPtr $ \skPtr ->
        SizedBS.useAsCString ct $ \ctPtr ->
            withForeignPtr ssFPtr $ \ssPtr -> do
                res <- c_dec ssPtr (castPtr ctPtr) skPtr
                when (res /= 0) $ error ("Decapsulation failed: " <> show res)

                SizedBS.create @SharedSecretBytes
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

{- | Encrypt and authenticate packet data using XSalsa20 and Poly1305
The data does not have to be the full packet, just part of the data

Produces a bytestring of length (16 + payload length)

nicer version of the packet_encrypt function in packet.c
-}
encryptPacketData ::
    forall payloadLen tag.
    ( KnownNat payloadLen
    , KnownNat (payloadLen + 16)
    , KnownNat (HashBytes + payloadLen)
    , 16 <= HashBytes + payloadLen
    , HashBytes + payloadLen - 16 ~ (payloadLen + 16)
    ) =>
    SizedByteString payloadLen ->
    Nonce tag ->
    SizedByteString HashBytes ->
    IO (SizedByteString (payloadLen + 16))
encryptPacketData payloadBS nonceBS keyBS = do
    let payloadLen = sizedLength payloadBS
        totalLen = hashBytes + payloadLen

    -- Allocate the full output buffer (Header + Payload)
    fullBuffer <- SizedBS.create @(HashBytes + payloadLen) $ \bufPtr -> do
        -- zero the first 32 bytes
        fillBytes bufPtr hashBytes 0

        -- copy payload
        SizedBS.useAsCStringLen payloadBS $ \(payloadPtr, copyLen) ->
            copyBytes (bufPtr `plusPtr` hashBytes) (castPtr payloadPtr) copyLen
        -- call xsalsa20_xor
        SizedBS.useAsCString (fullNonce nonceBS) $ \tempNoncePtr -> do
            SizedBS.useAsCString keyBS $ \tempKeyPtr -> do
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
    return (SizedBS.drop @16 fullBuffer)

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
    forall payloadLen nonce.
    ( HasCallStack
    , KnownNat payloadLen
    , KnownNat (16 + payloadLen)
    , KnownNat (32 + payloadLen)
    , 16 <= 16 + payloadLen
    , (16 + payloadLen) - 16 ~ payloadLen
    , (32 + payloadLen) - 32 ~ payloadLen
    , 32 <= 32 + payloadLen
    ) =>
    SizedByteString (16 + payloadLen) ->
    Nonce nonce ->
    SizedByteString HashBytes ->
    IO (SizedByteString payloadLen)
decryptPacketData encryptedBS nonceBS keyBS = do
    -- Sanity Checks

    let (cipherTag :: SizedByteString 16, ciphertext :: SizedByteString payloadLen) = SizedBS.splitAt @16 encryptedBS
        ctLen = SizedBS.sizedLength ciphertext
        totalLen = 32 + ctLen -- 32 bytes header + Ciphertext length
    fullBuffer <- SizedBS.create @(32 + payloadLen) $ \bufPtr -> do
        -- zero the header
        fillBytes bufPtr 32 0

        -- copy ciphertext to offset 32
        SizedBS.useAsCStringLen ciphertext $ \(ctPtr, len) ->
            copyBytes (bufPtr `plusPtr` 32) (castPtr ctPtr) len

        -- call xsalsa20_xor to generate the subkey and decrypt
        SizedBS.useAsCString (fullNonce nonceBS) \noncePtr -> do
            SizedBS.useAsCString keyBS \keyPtr -> do
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
                    when (polyRes /= 0) $ error
                        "Poly1305 Failed"
                        -- compare computed tag with provided tag
                        BS.useAsCStringLen
                        (fromSized cipherTag)
                        \(tagPtr, tagLen) -> do
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
    return (SizedBS.drop @32 fullBuffer)

mctinyHash :: BS.ByteString -> IO (SizedByteString HashBytes)
mctinyHash inputBS = do
    let inputLen = fromIntegral (BS.length inputBS) :: CULLong
    SizedBS.create \outputPtr ->
        BS.useAsCString inputBS \inputPtr -> do
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

publicKeyToMcTinyBlock ::
    McEliecePublicKey ->
    Int -> -- rowPos
    Int -> -- colPos
    IO (SizedByteString McTinyBlockBytes)
publicKeyToMcTinyBlock (McEliecePublicKey pkFPtr) rowPos colPos = do
    SizedBS.create $ \outPtr -> do
        withForeignPtr pkFPtr $ \pkPtr -> do
            c_mctiny_pk2block outPtr pkPtr (fromIntegral (rowPos - 1)) (fromIntegral (colPos - 1))

checkSeed :: SizedByteString CookieSeedBytes -> IO Bool
checkSeed seedBS = do
    SizedBS.useAsCString seedBS $ \seedPtr -> do
        res <- c_mctiny_seedisvalid (castPtr seedPtr)
        return (res /= 0)

seedToE ::
    SizedByteString CookieSeedBytes ->
    IO (SizedByteString McTinyErrorVectorBytes)
seedToE seedBS = do
    SizedBS.create $ \ePtr ->
        SizedBS.useAsCString seedBS $ \seedPtr -> do
            c_mctiny_seed2e ePtr (castPtr seedPtr)

eBlockToSyndrome ::
    SizedByteString McTinyErrorVectorBytes -> -- e
    SizedByteString McTinyBlockBytes -> -- block
    Int -> -- colPos
    IO (SizedByteString McTinySyndromeBytes)
eBlockToSyndrome eBS blockBS colPos = do
    SizedBS.create $ \sPtr ->
        -- create syndrome output
        SizedBS.useAsCString eBS \ePtr ->
            -- read e input
            SizedBS.useAsCString blockBS \blockPtr -> do
                -- read block input
                c_mctiny_eblock2syndrome
                    sPtr
                    (castPtr ePtr)
                    (castPtr blockPtr)
                    (fromIntegral colPos)

-- | Computes c_i,j ← K_i,j * e_j
computePartialSyndrome ::
    (HasCallStack) =>
    SizedByteString CookieSeedBytes ->
    SizedByteString McTinyBlockBytes ->
    Int -> -- colPos
    IO (SizedByteString McTinySyndromeBytes)
computePartialSyndrome seedBS blockBS colPos = do
    unless (colPos > 0 && colPos <= mcTinyColBlocks) $
        error $
            "Invalid column position: " <> show colPos
    eBS <- seedToE seedBS
    eBlockToSyndrome eBS blockBS (colPos - 1)

createPiece ::
    SizedByteString CookieSeedBytes ->
    Int -> -- piece index p (1-based)
    IO (SizedByteString McTinyPieceBytes)
createPiece seedBS piecePos = do
    eBS <- seedToE seedBS
    SizedBS.create $ \sPtr ->
        SizedBS.useAsCString eBS \ePtr -> do
            c_mctiny_pieceinit
                sPtr
                (castPtr ePtr)
                (fromIntegral (piecePos - 1))

absorbSyndromeIntoPiece ::
    SizedByteString McTinyPieceBytes ->
    SizedByteString McTinySyndromeBytes ->
    Int -> -- piece index (1-based)
    IO (SizedByteString McTinyPieceBytes) -- returns updated syndrome2
absorbSyndromeIntoPiece synd2BS synd1BS pieceIndex = do
    unless (pieceIndex > 0 && pieceIndex <= mctinyV) $
        error $
            "Invalid piece index: " <> show pieceIndex
    SizedBS.create $ \newSyndrome2Ptr ->
        -- create new syndrome2 result string
        SizedBS.useAsCString synd2BS \synd2Ptr -> do
            -- read synd2 input
            copyBytes newSyndrome2Ptr (castPtr synd2Ptr) (SizedBS.sizedLength synd2BS) -- copy input to output
            SizedBS.useAsCString synd1BS \synd1Ptr -> do
                -- read synd1 input
                c_mctiny_pieceabsorb
                    newSyndrome2Ptr -- output synd2
                    (castPtr synd1Ptr) -- input synd1
                    (fromIntegral (pieceIndex - 1)) -- piece index (0-based)

mergePieceSyndromes ::
    (HasCallStack) =>
    [SizedByteString McTinyPieceBytes] -> -- list of synd2
    IO (SizedByteString McTinyColBytes) -- returns merged synd3
mergePieceSyndromes synd2List = do
    let numPieces = length synd2List
    SizedBS.create @McTinyColBytes $ \synd3Ptr ->
        allocaBytes (numPieces * mctinyPieceBytes) $ \synd2ArrayPtr -> do
            -- copy each synd2 into the array
            forM_ (zip [0 ..] synd2List) $ \(i, synd2BS) -> do
                SizedBS.useAsCString synd2BS $ \synd2Ptr -> do
                    let destPtr = synd2ArrayPtr `plusPtr` (i * mctinyPieceBytes)
                    copyBytes destPtr (castPtr synd2Ptr) mctinyPieceBytes
            -- call the C function
            c_mctiny_mergepieces synd3Ptr synd2ArrayPtr
