{-# LANGUAGE AllowAmbiguousTypes #-}

module Packet.Generic where

import Data.ByteString.Lazy qualified as LBS

class KEMTLSPacket a where
    type PacketSize a :: Nat

    type PacketPutContext a
    -- ^ Context needed to put the packet

    type PacketGetContext a
    -- ^ Context needed to get the packet

    type PacketGetResult a
    -- ^ Result type when getting the packet

    getPacket :: (MonadIO m, Alternative m) => PacketGetContext a -> LBS.ByteString -> m (PacketGetResult a)
    putPacket :: (MonadIO m, Alternative m) => PacketPutContext a -> a -> m LBS.ByteString
