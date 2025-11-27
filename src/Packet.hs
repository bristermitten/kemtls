{-# LANGUAGE AllowAmbiguousTypes #-}

module Packet where

import Data.Binary
import Data.Binary.Get (getByteString, getWord16be, runGet)
import Data.Binary.Put
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import McTiny (SharedSecret, decryptPacketData, encryptPacketData)
import Utils
import Prelude hiding (ByteString, put)

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
          let _version = chVersion clientHello
          putByteString (chRandom clientHello)

          putWord8 (fromIntegral $ BS.length (chSessionID clientHello))
          putByteString (chSessionID clientHello)

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

    _length <- getByteString 3 -- Length is 3 bytes (why??)
    version <- getWord16be

    random <- getByteString 32

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
        , chRandom = random
        , chSessionID = sessionID
        , chCipherSuites = cipherSuites
        , chCompressionMethods = compressionMethods
        , chExtensions = []
        }

instance TLSRecord ClientHello where
  recordID = 0x1

data Packet
  = Handshake Handshake
  | McTiny McTinyC2SPacket

newtype Handshake
  = HandshakeClientHello ClientHello

data McTinyC2SPacket
  = Query0
      { query0Nonce :: ByteString -- should be 24 bytes long with the last 2 bytes zeroed
      , query0ServerPKHash :: ByteString -- sha3 hash of server's static public key (32 bytes)
      , query0CipherText :: ByteString -- encapsulation of server's static key (226 bytes)
      , query0Extensions :: [ByteString] -- currently unused, should be empty
      }
  | Query1
      { q1RowPos :: Int
      , q1ColPos :: Int
      , q1Block :: ByteString -- 1kb chunk of the public key
      , q1Nonce :: ByteString -- should be 24 bytes long with last 2 bytes encapsulating row and col
      , q1Cookie0 :: ByteString -- should be 16 bytes long
      }

data McTinyS2CPacket
  = Reply0
  { r0Cookie0 :: ByteString
  , r0Nonce :: ByteString
  }

class McTinyPacket a where
  putPacket :: SharedSecret -> a -> IO LBS.ByteString
  getPacket :: SharedSecret -> LBS.ByteString -> IO a

instance McTinyPacket McTinyC2SPacket where
  putPacket ss (Query0 nonce pkHash ct exts) = do
    guard (null exts) -- no extensions supported
    -- 512 0 bytes for extensions gets sent encrypted
    encrypted <- encryptPacketData (BS.replicate 512 0) nonce ss
    putStrLn "Packet encrypted"
    putStrLn $ "Packet Info: " ++ show (BS.length nonce, BS.length pkHash, BS.length ct, BS.length encrypted)
    pure $ runPut $ do
      putByteString encrypted
      putByteString pkHash
      putByteString ct
      putByteString nonce

  getPacket ss input = do
    let (mac, encrypted, pkHash, ct, nonce) =
          runGet
            ( do
                mac <- getByteString 16
                encrypted <- getByteString 512
                pkHash <- getByteString 32
                ct <- getByteString 226
                nonce <- getByteString 24
                pure (mac, encrypted, pkHash, ct, nonce)
            )
            input
    -- make sure last 2 bytes of nonce are zero
    guard (nonce `BS.index` 22 == 0 && nonce `BS.index` 23 == 0)

    decrypted <- decryptPacketData encrypted nonce ss

    pure $
      Query0
        { query0Nonce = nonce
        , query0ServerPKHash = pkHash
        , query0CipherText = ct
        , query0Extensions = [] -- no extensions supported
        }
