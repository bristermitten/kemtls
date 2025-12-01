{-# LANGUAGE AllowAmbiguousTypes #-}

module Protocol where

import Data.ByteString.Lazy qualified as LBS
import Network.Socket
import Network.Socket.ByteString.Lazy
import Packet
import Packet.Generic

recvPacket ::
    forall a m.
    (KEMTLSPacket a, KnownNat (PacketSize a), MonadIO m, HasCallStack) =>
    Socket ->
    PacketGetContext a ->
    m (PacketGetResult a)
recvPacket sock secret = do
    let size = fromIntegral $ natVal (Proxy @(PacketSize a))

    -- Read exact bytes
    packetData <- liftIO $ recvExact sock size
    if LBS.length packetData /= size
        then
            error $
                "Packet size mismatch in recvPacket! Expected "
                    <> show size
                    <> " bytes, but got "
                    <> show (LBS.length packetData)
                    <> " bytes."
        else
            liftIO $ getPacket @a secret packetData

sendPacket ::
    forall a.
    (KEMTLSPacket a, HasCallStack, KnownNat (PacketSize a), HasCallStack) =>
    Socket -> PacketPutContext a -> a -> IO ()
sendPacket sock secret packet = do
    packetData <- putPacket secret packet
    when (LBS.length packetData /= fromIntegral (natVal (Proxy @(PacketSize a)))) $
        error $
            "Packet size mismatch in sendPacket! Expected "
                <> show (natVal (Proxy @(PacketSize a)))
                <> " bytes, but got "
                <> show (LBS.length packetData)
                <> " bytes."
    sendAll sock packetData

recvExact :: (MonadIO m) => Socket -> Int64 -> m LBS.ByteString
recvExact sock n = liftIO $ go n
    where
        go 0 = return LBS.empty
        go remaining = do
            chunk <- recv sock remaining
            if LBS.null chunk
                then
                    error $
                        "Connection closed prematurely (recvExact)" <> show (n - remaining) <> " bytes received, " <> show remaining <> " bytes expected."
                else do
                    let len = LBS.length chunk
                    rest <- go (remaining - len)
                    return (chunk `LBS.append` rest)
