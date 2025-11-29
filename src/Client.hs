{-# LANGUAGE AllowAmbiguousTypes #-}

module Client where

import Client.State
import Control.Exception qualified as E
import McTiny
import Network.Socket
import Packet
import Protocol

-- | Read-only environment for the KEMTLS client
data ClientEnv = ClientEnv
    { envSocket :: Socket
    , envSharedSecret :: SharedSecret -- the result of ENC(pk),
    , envServerPublicKey :: McEliecePublicKey
    , localKeypair :: McElieceKeypair
    -- ^ Client's keypair (k, K)
    }

type ClientM a = ReaderT ClientEnv (StateT ClientState IO) a

runClient ::
    Maybe HostName ->
    ServiceName ->
    SharedSecret ->
    McEliecePublicKey ->
    McElieceKeypair ->
    ClientState ->
    ClientM a ->
    IO a
runClient mhost port ss serverPK localKP initialState action = do
    addr <- resolve
    E.bracket (open addr) close $ \sock -> do
        let env = ClientEnv sock ss serverPK localKP
        evalStateT (runReaderT action env) initialState
    where
        resolve = do
            let hints = defaultHints {addrSocketType = Stream}
            head <$> getAddrInfo (Just hints) mhost (Just port)

        open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
            connect sock $ addrAddress addr
            return sock

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

sendPacket ::
    ( McTinyPacket a
    , MonadIO m
    , KnownNat (PacketSize a)
    , PacketPutContext a ~ SharedSecret
    ) =>
    a -> ReaderT ClientEnv m ()
sendPacket packet = do
    sock <- asks envSocket
    secret <- asks envSharedSecret

    liftIO $ Protocol.sendPacket sock secret packet
