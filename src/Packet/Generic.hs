{-# LANGUAGE AllowAmbiguousTypes #-}

module Packet.Generic where

import Data.ByteString.Lazy qualified as LBS

{- | Type class abstracting over any packet type within our implementation.
It's a slightly misleading name as this also includes McTiny packets.
-}
class KEMTLSPacket a where
    type PacketSize a :: Nat
    -- ^ Expected size of the packet in bytes

    type PacketPutContext a
    -- ^ Context needed to put the packet

    type PacketGetContext a
    -- ^ Context needed to get the packet

    type PacketGetResult a
    -- ^ Result type when getting the packet

    -- | Serialize the packet into a lazy ByteString
    getPacket :: (MonadIO m, Alternative m) => PacketGetContext a -> LBS.ByteString -> m (PacketGetResult a)

    -- | Deserialize the packet from a lazy ByteString
    putPacket :: (MonadIO m, Alternative m) => PacketPutContext a -> a -> m LBS.ByteString
