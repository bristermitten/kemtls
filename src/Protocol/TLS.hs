{-# LANGUAGE AllowAmbiguousTypes #-}

module Protocol.TLS where

import Assertions (assertM)
import Constants (kemTLSMcTinyVersion)
import Data.Binary qualified
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Typeable
import Network.Socket
import Network.Socket.ByteString
import Packet.Generic
import Packet.TLS
import Protocol (recvExact)
import Transcript (TranscriptT)
import Transcript qualified

recvTLSRecord ::
    forall a m.
    ( MonadIO m
    , Alternative m
    , TLSRecord a
    , HasCallStack
    , MonadPlus m
    , KnownNat (PacketSize a)
    , KEMTLSPacket a
    , Typeable a
    ) =>
    Socket ->
    PacketGetContext a ->
    TranscriptT m (PacketGetResult a)
recvTLSRecord sock context = do
    let recordType = 0x16 -- Handshake

    -- Read record header
    recType <- liftIO $ recv sock 1
    ver <- liftIO $ recvExact sock 2
    lenBytes <- liftIO $ recvExact sock 2
    let expectedSize = fromIntegral $ natVal (Proxy @(PacketSize a))

    assertM
        (expectedSize >= fromIntegral (runGet getWord16be lenBytes))
        ("Client sent too many bytes: " <> show expectedSize <> " does not match length in TLS record header " <> show (runGet getWord16be lenBytes))
    assertM (recType == BS.pack [recordType]) ("TLS record type mismatch: expected " <> show recordType <> ", got " <> show recType)
    assertM (runGet getWord16be ver == kemTLSMcTinyVersion) ("TLS version mismatch: expected " <> show kemTLSMcTinyVersion <> ", got " <> show (runGet getWord16be ver))

    let len = fromIntegral (runGet getWord16be lenBytes)
    recordData <- liftIO (recvExact sock len)
    putStrLn $ "Recording packet of type: " <> show (typeRep (Proxy :: Proxy a))
    Transcript.recordMessage (fromLazy recordData)
    getPacket @a context recordData

sendTLSRecord ::
    forall a m.
    ( TLSRecord a
    , MonadIO m
    , MonadPlus m
    , Typeable a
    , KnownNat (PacketSize a)
    , HasCallStack
    ) =>
    Socket -> PacketPutContext a -> a -> TranscriptT m ()
sendTLSRecord sock context record = do
    let recordType = 0x16 -- Handshake
    let version = kemTLSMcTinyVersion -- KEMTLS v1.0
    body <- putPacket @a context record
    assertM
        (LBS.length body >= fromIntegral (natVal (Proxy @(PacketSize a))))
        ("Packet size mismatch when sending TLS record of type " <> show (typeRep (Proxy :: Proxy a)) <> ": expected " <> show (natVal (Proxy @(PacketSize a))) <> ", got " <> show (LBS.length body))

    putStrLn $ "Recording packet of type: " <> show (typeRep (Proxy :: Proxy a))
    Transcript.recordMessage (fromLazy body)
    let len = fromIntegral (LBS.length body) :: Word16
    let header = runPut $ do
            putWord8 recordType
            putWord16be version
            putWord16be len

    let packetData = header `LBS.append` body
    liftIO $ sendAll sock (fromLazy packetData)
