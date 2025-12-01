{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE UndecidableInstances #-}

module Packet.TLS where

import Assertions (assertM)
import Constants (CiphertextBytes, CookieC0Bytes, EncryptedSize, PacketNonceBytes)
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy qualified as LBS
import GHC.TypeLits (type (+))
import McTiny (Ciphertext, SharedSecret, decryptPacketData, encryptPacketData)
import Nonce
import Packet.Generic
import SizedByteString (SizedByteString, getSizedByteString, putSizedByteString)
import SizedByteString qualified as Sized

data ClientHello
    = ClientHello
    { chVersion :: Word16
    , chNonce :: Nonce "R"
    , chCiphertext :: Ciphertext
    }
    deriving stock (Show)

data ServerHello
    = ServerHello
    { shVersion :: Word16
    , shNonce :: Nonce "N"
    , shCookieC0 :: SizedByteString CookieC0Bytes
    -- ^ cookie c_0 must be encrypted!!!!
    }
    deriving stock (Show)

class (KEMTLSPacket a) => TLSRecord a where
    recordID :: Word8

instance KEMTLSPacket ClientHello where
    type
        PacketSize ClientHello =
            1 + PacketNonceBytes + CiphertextBytes
    type PacketPutContext ClientHello = ()
    type PacketGetContext ClientHello = ()
    type PacketGetResult ClientHello = ClientHello
    putPacket () clientHello = pure $ runPut $ do
        putWord8 (recordID @ClientHello)
        let body = runPut $ do
                putWord16be (chVersion clientHello)
                putNonce (chNonce clientHello)
                putSizedByteString (chCiphertext clientHello)
        let bodyBytes = body
        let bodyLength = fromIntegral (LBS.length bodyBytes) :: Word32
        put3ByteLength bodyLength
        putLazyByteString bodyBytes

    getPacket () input = pure $ flip runGet input $ do
        header <- getWord8
        assertM (header == recordID @ClientHello) "ClientHello record ID mismatch"

        _length <- get3ByteLength

        version <- getWord16be
        random <- getNonce
        ciphertext <- getSizedByteString

        pure $
            ClientHello
                { chVersion = version
                , chNonce = random
                , chCiphertext = ciphertext
                }

instance TLSRecord ClientHello where
    recordID = 0x1

instance KEMTLSPacket ServerHello where
    type
        PacketSize ServerHello =
            1 + PacketNonceBytes + EncryptedSize CookieC0Bytes

    type PacketPutContext ServerHello = SharedSecret
    type PacketGetContext ServerHello = SharedSecret
    type PacketGetResult ServerHello = ServerHello

    putPacket ss serverHello = do
        encrypted <- liftIO $ encryptPacketData serverHello.shCookieC0 serverHello.shNonce ss
        pure $ runPut $ do
            putWord8 (recordID @ServerHello)
            let body = runPut $ do
                    putWord16be (shVersion serverHello)
                    putNonce (shNonce serverHello)
                    putSizedByteString encrypted
            let bodyBytes = body
            let bodyLength = fromIntegral (LBS.length bodyBytes) :: Word32
            put3ByteLength bodyLength
            putLazyByteString bodyBytes

    getPacket ss input = do
        (encryptedCookie, version, nonce) <-
            pure $
                flip runGet input $ do
                    header <- getWord8
                    assertM (header == recordID @ServerHello) "ServerHello record ID mismatch"
                    _length <- get3ByteLength
                    version <- getWord16be
                    random <- getNonce
                    encryptedCookie <- getSizedByteString
                    pure (encryptedCookie, version, random)
        decryptedCookie <- liftIO $ decryptPacketData encryptedCookie nonce ss

        pure $
            ServerHello
                { shVersion = version
                , shNonce = nonce
                , shCookieC0 = decryptedCookie
                }

instance TLSRecord ServerHello where
    recordID = 0x2

put3ByteLength :: Word32 -> Put
put3ByteLength len = do
    putWord8 (fromIntegral (len `shiftR` 16))
    putWord8 (fromIntegral (len `shiftR` 8))
    putWord8 (fromIntegral len)

get3ByteLength :: Get Word32
get3ByteLength = do
    lengthBytes <- getSizedByteString @3
    let (b0, b1, b2) =
            ( Sized.index @0 lengthBytes
            , Sized.index @1 lengthBytes
            , Sized.index @2 lengthBytes
            )
    let len =
            fromIntegral b0 `shiftL` 16
                .|. fromIntegral b1 `shiftL` 8
                .|. fromIntegral b2 ::
                Word32
    pure len

data ClientFinished = ClientFinished
    {}
