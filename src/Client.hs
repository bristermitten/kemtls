module Client where

import Client.State
import Control.Exception qualified as E
import McTiny
import Network.Socket
import Network.Socket.ByteString.Lazy (recv, sendAll)
import Packet (McTinyC2SPacket, McTinyPacket (..))

data KemtlsClient = KemtlsClient
    { clientSocket :: Socket
    , ss :: SharedSecret -- the result of ENC(pk),
    , clientState :: ClientState
    }

type ClientM = StateT ClientState IO

kemtlsClient :: Maybe HostName -> ServiceName -> SharedSecret -> IO KemtlsClient
kemtlsClient mhost port ss = do
    addr <- resolve
    sock <- open addr
    putStrLn $ "Connected to server on port " <> port <> " on host " <> show addr
    return $ KemtlsClient sock ss Initial
    where
        resolve = do
            let hints = defaultHints {addrSocketType = Stream}
            head <$> getAddrInfo (Just hints) mhost (Just port)
        open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
            connect sock $ addrAddress addr
            return sock

sendPacket :: KemtlsClient -> McTinyC2SPacket -> IO ()
sendPacket client packet = do
    let sock = clientSocket client
    let secret = ss client
    packetData <- putPacket secret packet
    sendAll sock packetData

recvPacket :: forall a. (McTinyPacket a, KnownNat (PacketSize a)) => KemtlsClient -> IO a
recvPacket client = do
    let sock = clientSocket client
    let secret = ss client

    packetData <- recv sock (fromIntegral $ natVal $ Proxy @(PacketSize a))
    getPacket secret packetData

closeClient :: KemtlsClient -> IO ()
closeClient client = close (clientSocket client)
