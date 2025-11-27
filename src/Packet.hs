{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE UndecidableInstances #-}

module Packet where

import Constants
import Data.Binary
import Data.Binary.Get (getByteString, getWord16be, runGet)
import Data.Binary.Put
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import GHC.TypeLits (type (+))
import McTiny (SharedSecret, decryptPacketData, encryptPacketData)
import SizedByteString as SizedBS
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
        { query0Nonce :: SizedByteString PacketNonceBytes -- last 2 bytes zeroed
        , query0ServerPKHash :: SizedByteString HashBytes -- sha3 hash of server's static public key
        , query0CipherText :: SizedByteString 226 -- encapsulation of server's static key
        , query0Extensions :: [SizedByteString 0] -- currently unused, should be empty
        }
    | Query1
        { q1RowPos :: Int
        , q1ColPos :: Int
        , q1Block :: ByteString -- 1kb chunk of the public key
        , q1Nonce :: ByteString -- should be 24 bytes long with last 2 bytes encapsulating row and col
        , q1Cookie0 :: ByteString -- should be 16 bytes long
        }

class McTinyPacket a where
    type PacketSize a :: Nat
    putPacket :: (MonadIO m, Alternative m) => SharedSecret -> a -> m LBS.ByteString
    getPacket :: (MonadIO m, Alternative m) => SharedSecret -> LBS.ByteString -> m a

instance McTinyPacket McTinyC2SPacket where
    putPacket ss (Query0 nonce pkHash ct exts) = do
        guard (null exts) -- no extensions supported
        -- 512 0 bytes for extensions gets sent encrypted
        encrypted <- liftIO $ encryptPacketData (SizedBS.replicate @PacketExtensionsBytes 0) nonce ss
        putStrLn "Packet encrypted"
        putStrLn $ "Packet Info: " ++ show (SizedBS.sizedLength nonce, SizedBS.sizedLength pkHash, SizedBS.sizedLength ct, SizedBS.sizedLength encrypted)
        pure $ runPut $ do
            putSizedByteString encrypted
            putSizedByteString pkHash
            putSizedByteString ct
            putSizedByteString nonce

    getPacket ss input = do
        let (mac, encrypted, pkHash, ct, nonce) =
                runGet
                    ( do
                        mac <- getSizedByteString @16
                        encrypted <- getSizedByteString @PacketExtensionsBytes
                        pkHash <- getSizedByteString @32
                        ct <- getSizedByteString @226
                        nonce <- getSizedByteString @24
                        pure (mac, encrypted, pkHash, ct, nonce)
                    )
                    input
        -- make sure last 2 bytes of nonce are zero
        guard (SizedBS.index @22 nonce == 0 && SizedBS.index @23 nonce == 0)

        decrypted <- liftIO $ decryptPacketData encrypted nonce ss

        pure $
            Query0
                { query0Nonce = nonce
                , query0ServerPKHash = pkHash
                , query0CipherText = ct
                , query0Extensions = [] -- no extensions supported
                }

data Reply0 = Reply0
    { r0Cookie0 :: SizedByteString CookieC0Bytes
    , r0Nonce :: SizedByteString PacketNonceBytes
    }
    deriving stock (Show)

instance McTinyPacket Reply0 where
    type PacketSize Reply0 = CookieC0Bytes + 16 + PacketNonceBytes
    putPacket ss (Reply0 cookie nonce) = do
        encrypted <- liftIO $ encryptPacketData cookie nonce ss
        putStrLn "Reply0 packet encrypted"
        putStrLn $ "Reply0 Packet Info: " ++ show (SizedBS.sizedLength encrypted, SizedBS.sizedLength nonce)
        pure $ runPut $ do
            putSizedByteString encrypted
            putSizedByteString nonce

    getPacket ss input = do
        let (encryptedCookie, nonce) =
                runGet
                    ( do
                        encryptedCookie <- getSizedByteString @(CookieC0Bytes + 16)
                        nonce <- getSizedByteString @PacketNonceBytes
                        pure (encryptedCookie, nonce)
                    )
                    input
        decryptedCookie <- liftIO $ decryptPacketData encryptedCookie nonce ss
        pure $
            Reply0
                { r0Cookie0 = decryptedCookie
                , r0Nonce = nonce
                }
