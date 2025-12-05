{-# LANGUAGE AllowAmbiguousTypes #-}

-- | Library module for the KEMTLS client
module Client where

import Client.State
import Control.Exception qualified as E
import McTiny
import Network.Socket
import Packet.Generic
import Packet.McTiny (McTinyPacket)
import Protocol
import Transcript (TranscriptT, runTranscriptT)

-- | Read-only environment for the KEMTLS client
data ClientEnv = ClientEnv
    { envSocket :: Socket
    -- ^ Connected TCP socket
    , envSharedSecret :: SharedSecret
    -- ^ the result of ENC(pk), i.e. S or ss_s
    , envServerPublicKey :: McEliecePublicKey
    -- ^ Server's public key K
    , localKeypair :: McElieceKeypair
    -- ^ Client's keypair (k, K)
    }

-- | Monad stack for the KEMTLS client
type ClientM a = TranscriptT (ReaderT ClientEnv (StateT ClientState IO)) a

-- | Run a KEMTLS client action
runClient ::
    -- | Server hostname (Nothing for localhost)
    Maybe HostName ->
    -- | Server port
    ServiceName ->
    -- | Shared static secret established via KEM
    SharedSecret ->
    -- | Server's public key
    McEliecePublicKey ->
    -- | Client's keypair
    McElieceKeypair ->
    -- | Initial client state
    ClientState ->
    -- | Client action to run
    ClientM a ->
    IO a
runClient mhost port ss serverPK localKP initialState action = do
    addr <- resolve
    E.bracket (open addr) close $ \sock -> do
        let env = ClientEnv sock ss serverPK localKP
        evalStateT (runReaderT (runTranscriptT action) env) initialState
    where
        resolve = do
            let hints = defaultHints {addrSocketType = Stream}
            head <$> getAddrInfo (Just hints) mhost (Just port)

        open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
            connect sock $ addrAddress addr
            return sock

-- | Utility to read a McTiny packet from the server
readPacket ::
    forall a.
    ( McTinyPacket a
    , KnownNat (PacketSize a)
    , PacketGetContext a ~ SharedSecret
    ) =>
    ClientM (PacketGetResult a)
readPacket = do
    sock <- asks envSocket
    secret <- asks envSharedSecret

    Protocol.recvPacket @a sock secret

-- | Utility to read a McTiny packet from the server with a non-default context
readPacketWithContext ::
    forall a.
    ( McTinyPacket a
    , KnownNat (PacketSize a)
    ) =>
    PacketGetContext a ->
    ClientM (PacketGetResult a)
readPacketWithContext context = do
    sock <- asks envSocket
    Protocol.recvPacket @a sock context

-- | Utility to send a McTiny packet to the server
sendPacket ::
    ( McTinyPacket a
    , KnownNat (PacketSize a)
    , PacketPutContext a ~ SharedSecret
    , HasCallStack
    ) =>
    a -> ClientM ()
sendPacket packet = do
    sock <- asks envSocket
    secret <- asks envSharedSecret

    liftIO $ Protocol.sendPacket sock secret packet

-- | Utility to send a McTiny packet to the server with a non-default context
sendPacketWithContext ::
    ( McTinyPacket a
    , KnownNat (PacketSize a)
    , HasCallStack
    ) =>
    PacketPutContext a ->
    a ->
    ClientM ()
sendPacketWithContext context packet = do
    sock <- asks envSocket
    liftIO $ Protocol.sendPacket sock context packet
