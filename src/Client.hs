module Client where

import Client.State
import Control.Exception qualified as E
import McTiny
import Network.Socket
import Network.Socket.ByteString.Lazy (recv, sendAll)
import Packet (McTinyC2SPacket, McTinyPacket (..))

-- | Read-only environment for the KEMTLS client
data ClientEnv = ClientEnv
    { envSocket :: Socket
    , envSharedSecret :: SharedSecret -- the result of ENC(pk),
    , envServerPublicKey :: McEliecePublicKey
    }

type ClientM a = ReaderT ClientEnv (StateT ClientState IO) a

runClient :: Maybe HostName -> ServiceName -> SharedSecret -> McEliecePublicKey -> ClientState -> ClientM a -> IO a
runClient mhost port ss serverPK initialState action = do
    addr <- resolve
    E.bracket (open addr) close $ \sock -> do
        let env = ClientEnv sock ss serverPK
        evalStateT (runReaderT action env) initialState
    where
        resolve = do
            let hints = defaultHints {addrSocketType = Stream}
            head <$> getAddrInfo (Just hints) mhost (Just port)

        open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
            connect sock $ addrAddress addr
            return sock

sendPacket :: (McTinyPacket a, MonadIO m) => a -> ReaderT ClientEnv m ()
sendPacket packet = do
    sock <- asks envSocket
    secret <- asks envSharedSecret

    packetData <- liftIO $ putPacket secret packet
    liftIO $ sendAll sock packetData

recvPacket ::
    forall a m.
    (McTinyPacket a, KnownNat (PacketSize a), MonadIO m) =>
    ReaderT ClientEnv m a
recvPacket = do
    sock <- asks envSocket
    secret <- asks envSharedSecret

    let size = fromIntegral $ natVal (Proxy @(PacketSize a))

    -- Read exact bytes
    packetData <- liftIO $ recv sock size
    liftIO $ getPacket secret packetData
