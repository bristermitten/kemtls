module Client where

import Control.Exception qualified as E
import McTiny
import Network.Socket
import Network.Socket.ByteString.Lazy (recv, sendAll)
import Packet (McTinyC2SPacket, McTinyPacket (..))

data KemtlsClient = KemtlsClient
    { clientSocket :: Socket
    , ss :: SharedSecret -- the result of ENC(pk),
    }

kemtlsClient :: Maybe HostName -> ServiceName -> SharedSecret -> IO KemtlsClient
kemtlsClient mhost port ss = do
    addr <- resolve
    sock <- open addr
    putStrLn $ "Connected to server on port " <> port <> " on host " <> show addr
    return $ KemtlsClient sock ss
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

recvPacket :: (McTinyPacket a) => KemtlsClient -> IO a
recvPacket client = do
    let sock = clientSocket client
    let secret = ss client
    -- assuming max packet size of 2048 bytes
    packetData <- recv sock 2048
    getPacket secret packetData

closeClient :: KemtlsClient -> IO ()
closeClient client = close (clientSocket client)
