module ClientMain where

import Client
import Client.State
import Constants (NonceRandomPartBytes, mcTinyColBlocks, mcTinyRowBlocks, mctinyV)
import Data.ByteString qualified as BS
import Data.Vector.Fixed qualified as Fixed
import McTiny
import Nonce qualified
import Packet
import Paths
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
    putStrLn $ "Ciphertext: " ++ show ct
    putStrLn $ "Shared Secret: " ++ show ss

    let initialState = Initial {ct = ct}

    runClient (Just "127.0.0.1") "4433" ss serverPK keypair initialState $ do
        putStrLn "Starting KEMTLS client Phase 0..."
        runPhase0

runPhase0 :: ClientM ()
runPhase0 = do
    -- generate 176 random binary bits || 0, 0 for Query0.random
    nonce <-
        liftIO $
            randomSized @NonceRandomPartBytes
                <&> \r -> r `SizedBS.appendSized` Nonce.phase0C2SNonce
    putStrLn $ "Generated Query0.random: " ++ show nonce

    ct <- gets ct
    serverPK <- asks envServerPublicKey
    serverPKHash <- lift $ lift (publicKeyBytes serverPK >>= mctinyHash)
    putStrLn $ "Computed server public key hash: " ++ show serverPKHash
    sendPacket $
        Query0
            { query0NonceR = nonce
            , query0ServerPKHash = serverPKHash
            , query0CipherText = ct
            , query0Extensions = []
            }

    putStrLn "Client initialized."

    packet <- readPacket @Reply0

    putStrLn $ "Received Reply0 packet: " ++ show packet

    -- decode cookie
    let cookie = r0Cookie0 packet
    let longTermNonce = r0Nonce packet

    putStrLn $ "Stored Opaque Cookie (" ++ show (SizedBS.sizedLength cookie) ++ " bytes)"
    putStrLn "Handshake Phase 0 Complete."
    putStrLn $ "Long term nonce: " ++ show longTermNonce

    guard (SizedBS.index @22 longTermNonce == 1 && SizedBS.index @23 longTermNonce == 0)

    -- update client state
    put
        ( Phase1
            cookie
            (SizedBS.take @22 longTermNonce)
            emptyReceivedBlocks
        )
    runPhase1

runPhase1 :: ClientM ()
runPhase1 = do
    -- Placeholder for Phase 1 implementation
    liftIO $ putStrLn "Running Phase 1..."
    pk <- (.publicKey) <$> asks localKeypair

    cookie <- gets cookie0
    nonce <- gets longTermNonce

    for_ [1 .. mcTinyRowBlocks] $ \rowPos -> do
        for_ [1 .. mcTinyColBlocks] $ \colPos -> do
            liftIO $ putStrLn $ "Processing block (" ++ show rowPos ++ ", " ++ show colPos ++ ")"
            block <- liftIO $ pk2Block pk rowPos colPos

            let packetNonce =
                    SizedBS.take @22 nonce
                        `SizedBS.appendSized` Nonce.phase1C2SNonce rowPos colPos

            let queryPacket =
                    Query1
                        block
                        packetNonce
                        cookie

            sendPacket queryPacket
            putStrLn $ "Sent Query1 packet for block (" ++ show rowPos ++ ", " ++ show colPos ++ ")"

            receivedPacket <- readPacket @Reply1
            let reply1Nonce = r1Nonce receivedPacket

            unless (SizedBS.drop @22 reply1Nonce == Nonce.phase1S2CNonce rowPos colPos) $
                error $
                    "Client Error: Invalid Reply Nonce for Block "
                        <> show (rowPos, colPos)

            putStrLn $ "Received Reply1 packet: " ++ show receivedPacket
            modify
                ( \case
                    p1@Phase1 {} ->
                        p1
                            { receivedBlocks =
                                addBlock rowPos colPos (r1Cookie1 receivedPacket) (receivedBlocks p1)
                            }
                    _ -> error "Invalid client state when storing Reply1 blocks."
                )
    putStrLn "Handshake Phase 1 Complete."
    blocks <- gets receivedBlocks
    put (Phase2 cookie nonce blocks [])
    runPhase2

runPhase2 :: ClientM ()
runPhase2 = do
    allCookies <- gets receivedBlocks
    cookie0 <- gets cookie0
    for_ [1 .. ceiling (mcTinyRowBlocks / mctinyV)] $ \i -> do
        cookies <-
            forM [i * mctinyV - mctinyV + 1 .. i * mctinyV] $ \rowPos -> do
                forM [1 .. mcTinyColBlocks] $ \colPos -> do
                    case lookupBlock rowPos colPos allCookies of
                        Just block -> pure block
                        Nothing -> error $ "Missing block (" <> show rowPos <> ", " <> show colPos <> ")"
        let flatCookies = mconcat cookies
        print (length flatCookies, length cookies)
        nonce <- gets longTermNonce

        let packet =
                Query2
                    { query2Cookies = Fixed.fromList' flatCookies
                    , query2Cookie0 = cookie0
                    , query2Nonce = nonce `SizedBS.appendSized` Nonce.phase2C2SNonce i
                    }
        sendPacket packet
        putStrLn $ "Sent Query2 packet for cookie blocks " ++ show (i * mctinyV - mctinyV + 1) ++ " to " ++ show (i * mctinyV)

        reply <- readPacket @Reply2
        putStrLn $ "Received Reply2 packet: " ++ show reply
        modify
            ( \case
                ph2@(Phase2 {}) ->
                    ph2 {syndromes = syndromes ph2 ++ Fixed.toList (r2CJs reply)}
                _ -> error "Invalid client state when storing Reply2 syndromes."
            )

    putStrLn "Handshake Phase 2 Complete."
    runPhase3

runPhase3 :: ClientM ()
runPhase3 = do
    liftIO $ putStrLn "Running Phase 3..."

    syndromesList <- gets syndromes
    merged <- liftIO $ mergePieceSyndromes syndromesList
    nonce <- gets longTermNonce <&> (`SizedBS.appendSized` Nonce.phase3C2SNonce)
    cookie0 <- gets cookie0
    let packet =
            Query3
                { query3MergedPieces = merged
                , query3Nonce = nonce
                , query3Cookie0 = cookie0
                }
    print (fromSized merged)
    sendPacket packet
    putStrLn "Sent Query3 packet."

    reply <- readPacket @Reply3
    putStrLn $ "Received Reply3 packet: " ++ show reply

    sk <- (.secretKey) <$> asks localKeypair
    _Z <- liftIO $ decap sk (reply.reply3C || reply.reply3MergedPieces)
    putStrLn "Handshake Phase 3 Complete. Shared secret established."
    print _Z
