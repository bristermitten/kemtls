module ClientMain where

import Client
import Client.State
import Constants
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
import Prelude hiding ((||))

main :: IO ()
main = do
    keypair <- generateKeypair
    -- load server's public key
    serverPK <- readPublicKey pathToServerPublicKey
    putStrLn $ "Loaded server public key from " <> pathToServerPublicKey

    -- encapsulate a shared secret
    (ct, ss) <- encapsulate serverPK
    putStrLn $ "Ciphertext: " <> show ct
    putStrLn $ "Shared Secret: " <> show ss

    let initialState = Initial {ct = ct}

    runClient (Just "127.0.0.1") "4433" ss serverPK keypair initialState $ do
        putStrLn "Starting KEMTLS client Phase 0..."
        runClientHello

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

    socket <- asks envSocket
    Protocol.sendTLSRecord socket () clientHello

    dES <- kdf_dES
    putStrLn $ "Derived dES: " <> show dES
    putStrLn "ClientHello sent. Awaiting server response..."

    ss_s <- asks envSharedSecret
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

runPhase1 :: ClientM ()
runPhase1 = do
    -- Placeholder for Phase 1 implementation
    liftIO $ putStrLn "Running Phase 1..."
    pk <- (.publicKey) <$> asks localKeypair

    cookie <- gets cookie0
    nonce <- gets longTermNonce

    for_ [1 .. mcTinyRowBlocks] $ \rowPos -> do
        for_ [1 .. mcTinyColBlocks] $ \colPos -> do
            block <- liftIO $ publicKeyToMcTinyBlock pk rowPos colPos
            putStrLn $ "Requesting Block (" <> show rowPos <> "," <> show colPos <> ")"

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

runPhase2 :: SizedByteString CookieC0Bytes -> ClientM ()
runPhase2 cookie0 = do
    putStrLn "Running Phase 2..."
    allCookies <- gets receivedBlocks
    chts <- gets chts
    shts <- gets shts
    for_ [1 .. ceiling (mcTinyRowBlocks / mctinyV)] $ \i -> do
        cookies <-
            forM [i * mctinyV - mctinyV + 1 .. i * mctinyV] $ \rowPos -> do
                forM [1 .. mcTinyColBlocks] $ \colPos -> do
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

runPhase3 :: ClientM ()
runPhase3 = do
    liftIO $ putStrLn "Running Phase 3..."

    syndromesList <- gets syndromes
    merged <- liftIO $ mergePieceSyndromes syndromesList

    nonce <- gets longTermNonce <&> (`Nonce.withSuffix` Nonce.phase3C2SNonce)
    cookie0 <- gets cookie0
    let packet =
            Query3
                { query3MergedPieces = merged
                , query3Nonce = nonce
                , query3Cookie0 = cookie0
                }
    sendPacket packet
    putStrLn "Sent Query3 packet."

    reply <- readPacket @Reply3

    sk <- (.secretKey) <$> asks localKeypair
    _Z <- liftIO $ decap sk (reply.reply3MergedPieces || reply.reply3C)
    putStrLn "Handshake Phase 3 Complete. Shared secret established."
    print _Z
