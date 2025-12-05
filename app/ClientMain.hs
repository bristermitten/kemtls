module ClientMain where

import Assertions (assertM)
import Client
import Client.State
import Constants
import Data.ByteString qualified as BS
import Data.Map.Strict qualified as Map
import Data.Vector.Fixed qualified as Fixed
import KEMTLS
import McTiny
import Nonce (Nonce (nonceSuffix))
import Nonce qualified
import Packet
import Packet.TLS
import Paths
import Protocol.TLS qualified as Protocol
import SizedByteString
import SizedByteString qualified as SizedBS
import Transcript (getTranscriptHMAC)
import Prelude hiding ((||))

-- | Start the KEMTLS client
main :: IO ()
main = do
    keypair <- generateKeypair
    -- load server's public key
    serverPK <- readPublicKey pathToServerPublicKey
    putStrLn $ "Loaded server public key from " <> pathToServerPublicKey

    -- encapsulate the static public key to get ciphertext and shared secret (ss_S)
    (ct, ss) <- encapsulate serverPK
    putStrLn $ "Ciphertext: " <> show ct
    putStrLn $ "Shared Secret: " <> show ss

    let initialState = Initial {ct = ct}

    runClient (Just "127.0.0.1") "4433" ss serverPK keypair initialState $ do
        putStrLn "Starting KEMTLS client Phase 0..."
        runClientHello

-- | Run the ClientHello and process ServerHello
runClientHello :: ClientM ()
runClientHello = do
    putStrLn "Sending ClientHello..."
    ct <- gets ct

    let clientVersion = kemTLSMcTinyVersion -- KEMTLS v1.0
    nonceRandom <- liftIO $ randomSized @NonceRandomPartBytes
    let nonce =
            Nonce.parseNonce
                (nonceRandom `SizedBS.appendSized` Nonce.phase0C2SNonce)

    let clientHello =
            ClientHello
                { chVersion = clientVersion
                , chNonce = nonce
                , chCiphertext = ct
                }

    ss_s <- asks envSharedSecret
    dES <- deriveEarlySecret ss_s
    putStrLn $ "Derived dES: " <> show dES
    putStrLn "ClientHello sent. Awaiting server response..."

    socket <- asks envSocket
    Protocol.sendTLSRecord socket () clientHello

    response <- Protocol.recvTLSRecord @ServerHello socket ss_s
    putStrLn $ "Received ServerHello: " <> show response

    let cookie = shCookieC0 response
    let longTermNonce = shNonce response

    (chts, shts) <- deriveHandshakeSecret ss_s

    put
        ( Phase1
            cookie
            (Nonce.randomPart longTermNonce)
            emptyReceivedBlocks
            chts
            shts
        )

    putStrLn "Continuing McTiny as usual..."
    runPhase1 -- skip phase 0

-- | Run McTiny Phase 1 and transition to Phase 2
runPhase1 :: ClientM ()
runPhase1 = do
    -- Placeholder for Phase 1 implementation
    liftIO $ putStrLn "Running Phase 1..."
    pk <- (.publicKey) <$> asks localKeypair

    cookie <- gets cookie0
    nonce <- gets longTermNonce

    for_ [1 .. mcTinyRowBlocks] $ \rowPos ->
        for_ [1 .. mcTinyColBlocks] $ \colPos -> do
            block <- liftIO $ publicKeyToMcTinyBlock pk rowPos colPos

            let packetNonce =
                    nonce `Nonce.withSuffix` Nonce.phase1C2SNonce rowPos colPos

            let queryPacket =
                    Query1
                        block
                        packetNonce
                        cookie

            chts <- gets chts
            sendPacketWithContext chts queryPacket

            shts <- gets shts
            receivedPacket <- readPacketWithContext @Reply1 shts

            let reply1Nonce = r1Nonce receivedPacket

            unless (Nonce.nonceSuffix reply1Nonce == Nonce.phase1S2CNonce rowPos colPos) $
                error $
                    "Client Error: Invalid Reply Nonce for Block "
                        <> show (rowPos, colPos)

            modify
                ( \case
                    p1@Phase1 {} ->
                        p1
                            { receivedBlocks =
                                addBlock rowPos colPos (r1Cookie1 receivedPacket) (receivedBlocks p1)
                            }
                    _ -> error "Invalid client state when storing Reply1 blocks."
                )
    blocks <- gets receivedBlocks
    chts <- gets chts
    shts <- gets shts
    put (Phase2 cookie nonce blocks [] chts shts)
    runPhase2 cookie

-- | Run McTiny Phase 2 and transition to Phase 3
runPhase2 :: SizedByteString CookieC0Bytes -> ClientM ()
runPhase2 cookie0 = do
    putStrLn "Running Phase 2..."
    allCookies <- gets receivedBlocks
    assertM
        (length (ordNub $ Map.elems $ blocks allCookies) == mcTinyRowBlocks * mcTinyColBlocks)
        "Client Error: Incomplete blocks received in Phase 1."
    chts <- gets chts
    shts <- gets shts
    for_ [1 .. ceiling (mcTinyRowBlocks / mctinyV)] $ \i -> do
        cookies <-
            forM [i * mctinyV - mctinyV + 1 .. i * mctinyV] $ \rowPos -> forM [1 .. mcTinyColBlocks] $ \colPos -> do
                case lookupBlock rowPos colPos allCookies of
                    Just block -> pure block
                    Nothing -> error $ "Missing block (" <> show rowPos <> ", " <> show colPos <> ")"
        nonce <- gets longTermNonce
        let grid = Fixed.fromList' (map Fixed.fromList' cookies)
        let packet =
                Query2
                    { query2Cookies = grid
                    , query2Cookie0 = cookie0
                    , query2Nonce = nonce `Nonce.withSuffix` Nonce.phase2C2SNonce i
                    }
        sendPacketWithContext chts packet

        reply <- readPacketWithContext @Reply2 shts

        modify
            ( \case
                ph2@(Phase2 {}) ->
                    ph2 {syndromes = syndromes ph2 <> [r2Syndrome2 reply]}
                _ -> error "Invalid client state when storing Reply2 syndromes."
            )

    putStrLn "Handshake Phase 2 Complete."
    runPhase3

-- | Run McTiny Phase 3 and transition to Finished phase
runPhase3 :: ClientM ()
runPhase3 = do
    liftIO $ putStrLn "Running Phase 3..."

    syndromesList <- gets syndromes
    assertM
        (length (ordNub syndromesList) == ceiling (mcTinyRowBlocks / mctinyV))
        "Client Error: Incorrect number of syndromes collected in Phase 2."
    merged <- liftIO $ mergePieceSyndromes syndromesList

    chts <- gets chts
    shts <- gets shts
    nonce <- gets longTermNonce <&> (`Nonce.withSuffix` Nonce.phase3C2SNonce)
    cookie0 <- gets cookie0
    let packet =
            Query3
                { query3MergedPieces = merged
                , query3Nonce = nonce
                , query3Cookie0 = cookie0
                }

    sendPacketWithContext chts packet
    putStrLn "Sent Query3 packet."

    reply <- readPacketWithContext @Reply3 shts

    assertM
        (Nonce.nonceSuffix (reply3Nonce reply) == Nonce.phase3S2CNonce)
        "Client Error: Invalid Reply3 nonce suffix."

    sk <- (.secretKey) <$> asks localKeypair

    _Z <- liftIO $ decap sk (reply.reply3MergedPieces || reply.reply3C)
    putStrLn "Handshake Phase 3 Complete. Shared secret established."
    print _Z

    nonce <- gets longTermNonce
    ss_s <- asks envSharedSecret
    put
        ( Finalising
            nonce
            ss_s
            _Z
        )
    runFinishedPhase

{- | Run the Finished phase of the KEMTLS handshake, verifying ServerFinished and sending ClientFinished
Also sends a test application data packet after handshake completion
-}
runFinishedPhase :: ClientM ()
runFinishedPhase = do
    putStrLn "Running Finished Phase..."

    ss_s <- gets ss_s
    ss_e <- gets ss_e

    (chts, shts) <- deriveHandshakeSecret ss_s
    (fk_c, fk_s) <- deriveMasterSecret ss_s ss_e
    putStrLn $ "Derived fk_s: " <> show fk_s
    derivedHMAC <- getTranscriptHMAC fk_s

    socket <- asks envSocket
    serverFinished <- Protocol.recvTLSRecord @ServerFinished socket shts

    putStrLn $ "Received ServerFinished: " <> show serverFinished

    assertM
        (Nonce.nonceSuffix (sfNonce serverFinished) == Nonce.kemtlsNonceSuffix)
        "Client Error: Invalid ServerFinished nonce suffix."

    let expectedHMAC = sfHMAC serverFinished
    unless (derivedHMAC == expectedHMAC) $
        error "Client Error: ServerFinished HMAC does not match expected value!"
    putStrLn "ServerFinished HMAC verified successfully."

    cfHMAC <- getTranscriptHMAC fk_c
    ltNonce <- gets longTermNonce
    let newNonce =
            ltNonce `Nonce.withSuffix` Nonce.kemtlsNonceSuffix
    let clientFinished =
            ClientFinished
                { cfHMAC = cfHMAC
                , cfNonce = newNonce
                }
    Protocol.sendTLSRecord socket chts clientFinished

    putStrLn "Sent ClientFinished. Handshake complete."

    putStrLn "KEMTLS handshake successfully completed!"

    putStrLn "Sending test application data..."

    (cats, sats) <- deriveApplicationSecret ss_s ss_e

    let appData = SizedBS.mkSizedOrPad "Hello, secure world! KEMTLS and McTiny works :D"
    let appPacket =
            ApplicationData
                { adData = appData
                }

    Protocol.sendTLSRecord socket cats appPacket

    putStrLn "Test application data sent, waiting for server response..."

    response <- Protocol.recvTLSRecord @ApplicationData socket sats
    let rawMsg = SizedBS.toStrictBS $ adData response
    let cleanMsg = BS.takeWhile (/= 0) rawMsg
    putStrLn $
        "Received application data from server: "
            <> show cleanMsg

    putStrLn "Client session complete!!"
