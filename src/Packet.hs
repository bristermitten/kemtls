{-# LANGUAGE AllowAmbiguousTypes #-}

module Packet where

import Data.Binary
import Data.Binary.Get (getByteString, getBytes, getWord16be, getWord8, runGet)
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy qualified as LBS
import Prelude hiding (ByteString)

data ClientHello
  = ClientHello
  { chVersion :: Word16
  , chRandom :: ByteString
  , chSessionID :: ByteString
  , chCipherSuites :: [Word16]
  , chCompressionMethods :: [Word8]
  , chExtensions :: [(Word16, ByteString)]
  }
  deriving stock (Show)

data ServerHello
  = ServerHello
  { shLegacyVersion :: Word16
  , shRandom :: ByteString
  , shLegacySessionIDEcho :: ByteString
  , shCipherSuite :: Word16
  , shLegacyCompressionMethod :: Word8
  , shExtensions :: [(Word16, ByteString)]
  }
  deriving stock (Show)

class (Binary a) => TLSRecord a where
  recordID :: Word8

instance Binary ClientHello where
  put clientHello = do
    putWord8 (recordID @ClientHello)

    let payload = runPut $ do
          let version = chVersion clientHello
          putByteString (toStrict $ chRandom clientHello)

          putWord8 (fromIntegral $ LBS.length (chSessionID clientHello))
          putByteString (toStrict $ chSessionID clientHello)

          putWord16be (fromIntegral $ length (chCipherSuites clientHello) * 2)
          mapM_ putWord16be (chCipherSuites clientHello)

          putWord8 (fromIntegral $ length (chCompressionMethods clientHello))
          mapM_ putWord8 (chCompressionMethods clientHello)

          putWord16be 0 -- No extensions for now
    let payloadLen = fromIntegral (LBS.length payload) :: Word32
    putByteString (toStrict $ encodeNum24 payloadLen)
    putLazyByteString payload

  get = do
    header <- getWord8
    guard (header == recordID @ClientHello)

    length <- getByteString 3 -- Length is 3 bytes (why??)
    version <- getWord16be

    random <- getBytes 32

    sessionIDLen <- getWord8
    sessionID <- getByteString (fromIntegral sessionIDLen)

    cipherSuitesLen <- getWord16be
    cipherSuites <- replicateM (fromIntegral cipherSuitesLen `div` 2) getWord16be

    compressionMethodsLen <- getWord8
    guard (compressionMethodsLen == 1) -- Only null compression supported
    compressionMethods <- replicateM (fromIntegral compressionMethodsLen) getWord8

    extensionsLen <- getWord16be
    guard (extensionsLen == 0) -- we do not support extensions
    pure $
      ClientHello
        { chVersion = version
        , chRandom = toLazy random
        , chSessionID = toLazy sessionID
        , chCipherSuites = cipherSuites
        , chCompressionMethods = compressionMethods
        , chExtensions = []
        }

instance TLSRecord ClientHello where
  recordID = 0x1

data Packet
  = Handshake Handshake

data Handshake
  = HandshakeClientHello ClientHello

-- | Encode a 24-bit big-endian integer as a lazy ByteString
encodeNum24 :: Word32 -> LBS.ByteString
encodeNum24 w =
  LBS.pack [fromIntegral (w `shiftR` 16), fromIntegral (w `shiftR` 8), fromIntegral w]
