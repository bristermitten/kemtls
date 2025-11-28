{-# LANGUAGE AllowAmbiguousTypes #-}

module Protocol where

import Data.ByteString.Lazy qualified as LBS
import GHC.TypeLits (type (+))
import Network.Socket
import Network.Socket.ByteString.Lazy
import Packet
import SizedByteString

recvPacket ::
    forall a m.
    (McTinyPacket a, KnownNat (PacketSize a), MonadIO m) =>
    Socket ->
    PacketGetContext a ->
    m (PacketGetResult a)
recvPacket sock secret = do
    let size = fromIntegral $ natVal (Proxy @(PacketSize a))

    -- Read exact bytes
    packetData <- liftIO $ recv sock size
    liftIO $ getPacket @a secret packetData

sendPacket :: forall a. (McTinyPacket a, KnownNat (PacketSize a)) => Socket -> PacketPutContext a -> a -> IO ()
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
