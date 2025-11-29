module Server where

import Control.Concurrent (forkFinally, modifyMVar_)
import Control.Exception qualified as E

import Constants
import Control.Monad.Except (MonadError, throwError)
import Cookie
import Crypto.Random
import Data.Vector.Fixed qualified as Fixed
import McTiny (McElieceSecretKey, SharedSecret, absorbSyndromeIntoPiece, computePartialSyndrome, computePieceSyndrome, encryptPacketData, mctinyHash, seedToE)
import Network.Socket
import Nonce qualified
import Packet
import Protocol qualified
import Server.State
import SizedByteString as SizedBS
import Prelude hiding ((||))

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

                serverState <- readMVar stateVar
                let cid = length (connectedClients serverState) + 1

                -- Create the initial Local State for this client
                let clientLocalState = newClient cid conn

                forkFinally
                    (runStateT (runReaderT handleConnection stateVar) clientLocalState)
                    ( \result -> do
                        case result of
                            Left ex -> putStrLn $ "Thread crashed:\n" <> displayException ex
                            Right _ -> putStrLn "Thread finished normally"
                        cleanupClient stateVar cid conn
                    )

newClient :: Int -> Socket -> ClientInfo
newClient cid sock =
    ClientInfo
        { clientId = cid
        , clientSocket = sock
        , clientState = Initialised
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

setClientState :: (MonadTrans t, MonadState ClientInfo m) => ClientState -> t m ()
setClientState newState = do
    lift $ modify $ \c -> c {clientState = newState}

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
    client <- lift Prelude.get
    putStrLn $ "Client " ++ show (clientId client) ++ " in state: " ++ show (clientState client)
    case clientState client of
        Initialised -> do
            putStrLn "Waiting for Query0..."
            processQuery0
            handshakeLoop
        SentReply0 {} -> do
            putStrLn "Waiting for Query1..."
            processQuery1
            handshakeLoop
        SentReply1 {} -> do
            putStrLn "Waiting for Query2..."
            processQuery2
            handshakeLoop
        Phase3 {} -> do
            putStrLn "Waiting for Query3..."
            processQuery3
        -- dont loop, handshake complete
        Completed -> do
            error "Client already completed handshake, expected no further messages."

processQuery0 :: ExceptT Text ConnectionM ()
processQuery0 = do
    client <- lift (lift Prelude.get)
    let conn = clientSocket client

    stateVar <- lift ask
    globalState <- liftIO $ readMVar stateVar

    (query0, ss) <- lift $ Protocol.recvPacket @Query0 conn globalState
    print query0

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

    setClientState (SentReply0 ss)

processQuery1 :: ExceptT Text ConnectionM ()
processQuery1 = do
    client <- lift (lift Prelude.get)
    let conn = clientSocket client
    let ss = case clientState client of
            SentReply0 secret -> secret
            _ -> error "Invalid client state in processQuery1"

    for_ [1 .. mcTinyRowBlocks] $ \rowPos -> do
        for_ [1 .. mcTinyColBlocks] $ \colPos -> do
            _packet <- lift $ Protocol.recvPacket @Query1 conn ss
            (ss, s_m, s, nonceM, e) <-
                lift $
                    handleC0AndMAndSM
                        (q1Cookie0 _packet)
                        (q1Nonce _packet)

            globalState <- lift getGlobalState

            -- verify last 2 bytes of nonce are what we'd expect
            expect
                (SizedBS.drop @22 (q1Nonce _packet) == Nonce.phase1C2SNonce rowPos colPos)
                ("Invalid nonce in Query1 for block (" <> show rowPos <> "," <> show colPos <> ")")

            -- compute c_i,j
            syndrome <- liftIO $ computePartialSyndrome e (q1Block _packet) colPos

            (cookie1, nonceN) <- liftIO $ createCookie1 (cookieSecretKey globalState) syndrome (q1Nonce _packet) rowPos colPos 0

            let reply =
                    Reply1
                        { r1Cookie0 = q1Cookie0 _packet
                        , r1Cookie1 = cookie1
                        , r1Nonce = nonceM `SizedBS.appendSized` Nonce.phase1S2CNonce rowPos colPos
                        }
            liftIO $ sendPacket client ss reply
            putStrLn $ "Processed Block (" ++ show rowPos ++ "," ++ show colPos ++ ")"
    putStrLn "Completed processing Query1."
    setClientState (SentReply1 ss)

processQuery2 :: ExceptT Text ConnectionM ()
processQuery2 = do
    client <- lift (lift Prelude.get)
    let conn = clientSocket client
    let ss = case clientState client of
            SentReply1 secret -> secret
            _ -> error "Invalid client state in processQuery1"

    for_ [1 .. ceiling (mcTinyRowBlocks / mctinyV)] $ \i -> do
        -- i
        packet <- lift $ Protocol.recvPacket @Query2 conn ss
        putStrLn $ "Received Query2 packet: " ++ show packet

        globalState <- lift getGlobalState
        (ss, s_m, s, nonceM, e) <- lift $ handleC0AndMAndSM (query2Cookie0 packet) (query2Nonce packet)

        let piecePos =
                case Nonce.decodePhase2C2SNonce (SizedBS.drop @22 (query2Nonce packet)) of
                    Just pos -> pos
                    Nothing -> error "Invalid nonce in Query2"

        syndrome <- liftIO $ computePieceSyndrome e piecePos

        cookiesAndNonces <- flip Fixed.mapM (query2Cookies packet) $ \cookie1 -> do
            (decoded, nonceM) <-
                liftIO $
                    decodeCookie1
                        (cookieSecretKey globalState)
                        cookie1
                        (query2Nonce packet)
                        (piecePos * mctinyV - mctinyV + 1)
                        (piecePos * mctinyV)

            syndrome2 <- liftIO $ absorbSyndromeIntoPiece syndrome decoded piecePos
            pure (syndrome2, nonceM)

        let cJs = Fixed.map fst cookiesAndNonces
        let _noncesM = Fixed.map snd cookiesAndNonces

        liftIO $
            sendPacket client ss $
                Reply2
                    { r2Cookie0 = query2Cookie0 packet
                    , r2CJs = cJs
                    , r2Nonce = nonceM || Nonce.phase2S2CNonce piecePos
                    }

    setClientState (Phase3 ss)

processQuery3 :: ExceptT Text ConnectionM ()
processQuery3 = do
    client <- lift (lift Prelude.get)
    let conn = clientSocket client
    let ss = case clientState client of
            Phase3 secret -> secret
            _ -> error "Invalid client state in processQuery3"

    packet <- lift $ Protocol.recvPacket @Query3 conn ss

    (ss, s_m, s, nonceM, _E) <- lift $ handleC0AndMAndSM (query3Cookie0 packet) (query3Nonce packet)
    e <- liftIO $ seedToE _E

    _C <- liftIO $ mctinyHash ("2" <> fromSized e)
    _Z <- liftIO $ mctinyHash ("1" <> fromSized e <> fromSized (query3MergedPieces packet) <> fromSized _C)

    s_mHash <- liftIO $ mctinyHash (fromSized s_m)
    let mNonce = nonceM || Nonce.phase3S2CNonce
    _C_Z <-
        liftIO $
            encryptPacketData _Z mNonce s_mHash
                <&> (`snocSized` 0) -- m = 0
    sendPacket client ss $
        Reply3
            { reply3C_z = _C_Z
            , reply3C = _C
            , reply3MergedPieces = query3MergedPieces packet
            , reply3Nonce = mNonce
            }
    putStrLn $ "Received Query3 packet: " ++ show packet

handleC0AndMAndSM ::
    SizedByteString CookieC0Bytes ->
    SizedByteString PacketNonceBytes ->
    ConnectionM
        ( SharedSecret
        , SizedByteString SessionKeyBytes
        , SizedByteString HashBytes
        , SizedByteString NonceRandomPartBytes
        , SizedByteString CookieSeedBytes
        )
handleC0AndMAndSM c0 nonce = do
    globalState <- getGlobalState
    (ss, e) <- liftIO $ decodeCookie0 (cookieSecretKey globalState) c0 nonce
    let s_m :: SizedByteString SessionKeyBytes = SizedBS.replicate 0 -- current cookie key, but we don't do rotation so always 0
    -- we would have to recreate C_0 here but since s_m hasn't changed there's nothing to do
    mNonce <-
        liftIO $
            randomSized @NonceRandomPartBytes
    s <- liftIO $ mctinyHash (fromSized (s_m || e))

    pure (ss, s_m, s, mNonce, e)

getGlobalState :: ConnectionM ServerState
getGlobalState = do
    stateVar <- ask
    liftIO $ readMVar stateVar

sendPacket ::
    ( McTinyPacket a
    , KnownNat (PacketSize a)
    , MonadIO m
    ) =>
    ClientInfo -> PacketPutContext a -> a -> m ()
sendPacket client context packet = do
    let sock = clientSocket client

    liftIO $ Protocol.sendPacket sock context packet

expect :: (MonadError e f) => Bool -> e -> f ()
expect True _ = pass
expect False errMsg = throwError errMsg
