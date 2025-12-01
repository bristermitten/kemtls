{-# LANGUAGE AllowAmbiguousTypes #-}

module Packet.TLS where

import Constants (CookieC0Bytes)
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import McTiny (Ciphertext)
import Nonce
import SizedByteString (SizedByteString, getSizedByteString, putSizedByteString)

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
    }
    deriving stock (Show)

class (Binary a) => TLSRecord a where
    recordID :: Word8

instance Binary ClientHello where
    put clientHello = do
        putWord8 (recordID @ClientHello)
        let body = runPut $ do
                putWord16be (chVersion clientHello)
                putNonce (chNonce clientHello)
                putSizedByteString (chCiphertext clientHello)
        let bodyBytes = body
        let bodyLength = fromIntegral (LBS.length bodyBytes) :: Word32
        -- Write length as 3 bytes (24-bit big-endian)
        putWord8 (fromIntegral (bodyLength `shiftR` 16))
        putWord8 (fromIntegral (bodyLength `shiftR` 8))
        putWord8 (fromIntegral bodyLength)
        putLazyByteString bodyBytes

    get = do
        header <- getWord8
        guard (header == recordID @ClientHello)

        -- Read 3-byte length (24-bit big-endian)
        lengthBytes <- getByteString 3
        let [b0, b1, b2] = BS.unpack lengthBytes
        let _length =
                (fromIntegral b0 `shiftL` 16)
                    .|. (fromIntegral b1 `shiftL` 8)
                    .|. fromIntegral b2 ::
                    Word32

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

instance Binary ServerHello where
    put serverHello = do
        putWord8 (recordID @ServerHello)
        let body = runPut $ do
                putWord16be (shVersion serverHello)
                putNonce (shNonce serverHello)
                putSizedByteString (shCookieC0 serverHello)
        let bodyBytes = body
        let bodyLength = fromIntegral (LBS.length bodyBytes) :: Word32
        -- Write length as 3 bytes (24-bit big-endian)
        putWord8 (fromIntegral (bodyLength `shiftR` 16))
        putWord8 (fromIntegral (bodyLength `shiftR` 8))
        putWord8 (fromIntegral bodyLength)
        putLazyByteString bodyBytes

    get = do
        header <- getWord8
        guard (header == recordID @ServerHello)
        -- Read 3-byte length (24-bit big-endian)
        lengthBytes <- getByteString 3
        let [b0, b1, b2] = BS.unpack lengthBytes
        let _length =
                (fromIntegral b0 `shiftL` 16)
                    .|. (fromIntegral b1 `shiftL` 8)
                    .|. fromIntegral b2 ::
                    Word32
        version <- getWord16be
        random <- getNonce
        cookieC0 <- getSizedByteString
        pure $
            ServerHello
                { shVersion = version
                , shNonce = random
                , shCookieC0 = cookieC0
                }

instance TLSRecord ServerHello where
    recordID = 0x2
