module Server where

import Control.Concurrent (forkFinally, modifyMVar_)
import Control.Exception qualified as E

import Constants
import Control.Monad.Except (MonadError, throwError)
import Crypto.Random
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put (runPut)
import Data.Bits
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import GHC.TypeLits (type (+))
import McTiny (McElieceSecretKey, SharedSecret, createCookie0, decap, decryptPacketData)
import Network.Socket
import Network.Socket.ByteString.Lazy
import Network.Transport.Internal (decodeNum16)
import Packet
import Server.State
import SizedByteString as SizedBS
import Utils

type ServerEnv = MVar ServerState
type ConnectionM = ReaderT ServerEnv (StateT ClientInfo IO)

kemtlsServer :: Maybe HostName -> ServiceName -> McElieceSecretKey -> IO ()
kemtlsServer mhost port serverSecretKey = do
    addr <- resolve
    drg <- getSystemDRG
    cookieKey <- randomSized @32
    stateVar <-
        newMVar
            ( ServerState
                []
                serverSecretKey
                cookieKey
            )

    vacuous $ E.bracket (open addr) close (loop stateVar)
    where
        resolve = do
            let hints =
                    defaultHints
                        { addrFlags = [AI_PASSIVE]
                        , addrSocketType = Stream
                        , addrProtocol = 6 -- TCP
                        }
            head <$> getAddrInfo (Just hints) mhost (Just port)
        open addr = E.bracketOnError (openSocket addr) close $ \sock -> do
            setSocketOption sock ReuseAddr 1
            withFdSocket sock setCloseOnExecIfNeeded
            bind sock $ addrAddress addr
            listen sock 1024
            putStrLn $ "Listening on port " <> port <> " on host " <> show addr
            return sock

        loop stateVar sock = infinitely $
            E.bracketOnError (accept sock) (close . fst) $ \(conn, peer) -> do
                putStrLn $ "Connection from " ++ show peer

                -- Generate a simplified ID (e.g., file descriptor or random)
                let cid = 1 -- In real code, increment a counter in ServerState

                -- Create the initial Local State for this client
                let clientLocalState = newClient cid conn

                forkFinally
                    (runStateT (runReaderT handleConnection stateVar) clientLocalState)
                    (\_ -> cleanupClient stateVar cid conn)

newClient :: Int -> Socket -> ClientInfo
newClient cid sock =
    ClientInfo
        { clientId = cid
        , clientSocket = sock
        , -- , clientSharedSecret = Nothing
          clientState = Initialised
        , clientCookieMemory = emptyClientCookies
        }

registerClient :: ConnectionM ()
registerClient = do
    stateVar <- ask
    client <- Prelude.get

    liftIO $ modifyMVar_ stateVar $ \st -> do
        let newClients = client : connectedClients st
        putStrLn $ "Client registered. Clients connected: " ++ show (length newClients)
        return $ st {connectedClients = newClients}

updateClientState :: (MonadTrans t, MonadState ClientInfo m) => (ClientState -> ClientState) -> t m ()
updateClientState transition = do
    lift $ modify $ \c -> c {clientState = transition (clientState c)}

cleanupClient :: MVar ServerState -> Int -> Socket -> IO ()
cleanupClient stateVar cid sock = do
    close sock
    modifyMVar_ stateVar $ \st -> do
        let remainingClients = filter (\c -> clientId c /= cid) (connectedClients st)
        putStrLn $ "Client disconnected. Clients connected: " ++ show (length remainingClients)
        return $ st {connectedClients = remainingClients}

handleConnection :: ConnectionM ()
handleConnection = do
    registerClient

    result <- runExceptT handshakeLoop

    case result of
        Left err -> liftIO $ putTextLn $ "Client Error: " <> err
        Right _ -> liftIO $ putTextLn "Client Finished successfully."

handshakeLoop :: ExceptT Text ConnectionM ()
handshakeLoop = do
    client <- lift (lift Prelude.get)
    case clientState client of
        Initialised -> do
            liftIO $ putStrLn "Waiting for Query0..."
            processQuery0

processQuery0 :: ExceptT Text ConnectionM ()
processQuery0 = do
    client <- lift (lift Prelude.get)
    let conn = clientSocket client

    stateVar <- lift ask
    globalState <- liftIO $ readMVar stateVar
    let serverSK = serverSecretKey globalState

    encryptedExtensions <- recvExact @(PacketExtensionsBytes + 16) conn
    putStrLn "Received valid MAC and extensions from client"
    pkHash <- recvExact @HashBytes conn -- todo verify this matches server public key hash
    ct <- recvExact @CiphertextBytes conn
    nonce <- recvExact @PacketNonceBytes conn
    expect (SizedBS.index @22 nonce == 0 && SizedBS.index @23 nonce == 0) "Invalid nonce received from client"

    ss <- liftIO $ decap serverSK (SizedBS.lazyToStrict ct)
    putStrLn $ "Decapsulated shared secret: " ++ show ss

    extensions <- liftIO $ decryptPacketData (SizedBS.lazyToStrict encryptedExtensions) (SizedBS.lazyToStrict nonce) ss
    putStrLn $ "Decrypted extensions: " ++ show extensions
    -- assert that extensions are 512 zero bytes
    expect (extensions == SizedBS.replicate @PacketExtensionsBytes 0) "Invalid extensions received from client"

    drg <- liftIO getSystemDRG
    -- generate 176 random binary bits || 0, 0 for ClientHello.random
    let (randomBytes :: ByteString, drg') = withRandomBytes drg (176 `div` 8) $ \bs ->
            bs <> BS.pack [0, 0] -- last 2 bytes zeroed
    putStrLn $ "Generated Reply0.random: " ++ show randomBytes

    -- generate 32 byte seed
    seed <- liftIO $ randomSized @CookieSeedBytes
    putStrLn $ "Generated Reply0.seed: " ++ show seed

    (cookie, nonce) <- liftIO $ createCookie0 (cookieSecretKey globalState) ss seed 0

    let packet =
            Reply0
                { r0Cookie0 = cookie
                , r0Nonce = nonce
                }

    liftIO $ sendPacket client ss packet

    -- update client state
    updateClientState (const (SentReply0 ss))

sendPacket :: (McTinyPacket a) => ClientInfo -> SharedSecret -> a -> IO ()
sendPacket client secret packet = do
    let sock = clientSocket client

    packetData <- putPacket secret packet
    sendAll sock packetData

expect :: (MonadError e f) => Bool -> e -> f ()
expect True _ = pass
expect False errMsg = throwError errMsg

recvExact :: forall i m. (MonadIO m, KnownNat i) => Socket -> m (SizedLazyByteString i)
recvExact sock = do
    let totalBytes = fromIntegral (natVal (Proxy @i))
    received <- liftIO $ recvExact' sock totalBytes LBS.empty
    case mkSized received of
        Just sized -> return sized
        Nothing -> error "Received incorrect number of bytes"
    where
        recvExact' :: Socket -> Int -> LBS.ByteString -> IO LBS.ByteString
        recvExact' _ 0 acc = return acc
        recvExact' s n acc = do
            chunk <- recv s (fromIntegral n)
            if LBS.null chunk
                then error "Not enough data received"
                else do
                    let restLen = n - fromIntegral (LBS.length chunk)
                    recvExact' s restLen (acc `LBS.append` chunk)
