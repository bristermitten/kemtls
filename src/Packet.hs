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
import McTiny (SharedSecret, decap, decryptPacketData, encryptPacketData)
import Server.State (ServerState (..))
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

newtype Packet
    = Handshake Handshake

newtype Handshake
    = HandshakeClientHello ClientHello

data Query0
    = Query0
    { query0Nonce :: SizedByteString PacketNonceBytes -- last 2 bytes zeroed
    , query0ServerPKHash :: SizedByteString HashBytes -- sha3 hash of server's static public key
    , query0CipherText :: SizedByteString 226 -- encapsulation of server's static key
    , query0Extensions :: [SizedByteString 0] -- currently unused, should be empty
    }
    deriving stock (Show)

data Query1
    = Query1
    { q1Block :: SizedByteString McTinyBlockBytes -- 1kb chunk of the public key
    , q1Nonce :: SizedByteString PacketNonceBytes -- should be 24 bytes long with last 2 bytes encapsulating row and col
    , q1Cookie0 :: SizedByteString CookieC0Bytes
    }

class McTinyPacket a where
    type PacketSize a :: Nat

    type PacketPutContext a
    -- ^ Context needed to put the packet

    type PacketGetContext a
    -- ^ Context needed to get the packet

    type PacketGetResult a
    -- ^ Result type when getting the packet

    putPacket :: (MonadIO m, Alternative m) => PacketPutContext a -> a -> m LBS.ByteString
    getPacket :: (MonadIO m, Alternative m) => PacketGetContext a -> LBS.ByteString -> m (PacketGetResult a)

instance McTinyPacket Query0 where
    type PacketSize Query0 = EncryptedSize PacketNonceBytes + HashBytes + 226 + PacketExtensionsBytes

    type PacketPutContext Query0 = SharedSecret
    type PacketGetContext Query0 = ServerState
    type PacketGetResult Query0 = (Query0, SharedSecret)
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

    getPacket serverState input = do
        let (mac, encrypted, pkHash, ct, nonce) =
                runGet
                    ( do
                        mac <- getSizedByteString @16
                        encrypted <- getSizedByteString @PacketExtensionsBytes
                        pkHash <- getSizedByteString @HashBytes
                        ct <- getSizedByteString @CiphertextBytes
                        nonce <- getSizedByteString @PacketNonceBytes
                        pure (mac, encrypted, pkHash, ct, nonce)
                    )
                    input
        -- make sure last 2 bytes of nonce are zero
        guard (SizedBS.index @22 nonce == 0 && SizedBS.index @23 nonce == 0)

        ss <- liftIO $ decap (serverSecretKey serverState) ct
        decryptedExtensions <- liftIO $ decryptPacketData (mac `SizedBS.appendSized` encrypted) nonce ss
        -- assert that extensions are 512 zero bytes
        guard (decryptedExtensions == SizedBS.replicate @PacketExtensionsBytes 0)

        pure
            ( Query0
                { query0Nonce = nonce
                , query0ServerPKHash = pkHash
                , query0CipherText = ct
                , query0Extensions = [] -- no extensions supported
                }
            , ss
            )

instance McTinyPacket Query1 where
    type PacketSize Query1 = McTinyBlockBytes + 16 + CookieC0Bytes + PacketNonceBytes
    type PacketPutContext Query1 = SharedSecret
    type PacketGetContext Query1 = SharedSecret
    type PacketGetResult Query1 = Query1
    putPacket ss (Query1 block nonce cookie) = do
        encrypted <- liftIO $ encryptPacketData block nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putSizedByteString cookie
            putSizedByteString nonce

    getPacket ss input = do
        let (encryptedBlock, cookie, nonce) =
                flip runGet input $ do
                    encryptedBlock <- getSizedByteString @(McTinyBlockBytes + 16)
                    cookie <- getSizedByteString @CookieC0Bytes
                    nonce <- getSizedByteString @PacketNonceBytes
                    pure (encryptedBlock, cookie, nonce)
        decryptedBlock <- liftIO $ decryptPacketData encryptedBlock nonce ss
        pure $
            Query1
                { q1Block = decryptedBlock
                , q1Nonce = nonce
                , q1Cookie0 = cookie
                }

data Reply0 = Reply0
    { r0Cookie0 :: SizedByteString CookieC0Bytes
    , r0Nonce :: SizedByteString PacketNonceBytes
    }
    deriving stock (Show)

instance McTinyPacket Reply0 where
    type PacketSize Reply0 = CookieC0Bytes + 16 + PacketNonceBytes
    type PacketPutContext Reply0 = SharedSecret
    type PacketGetContext Reply0 = SharedSecret
    type PacketGetResult Reply0 = Reply0
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
