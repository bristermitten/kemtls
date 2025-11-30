module ClientMain where

import Client
import Client.State
import Constants (CookieC0Bytes, CookieSeedBytes, NonceRandomPartBytes, mcTinyColBlocks, mcTinyRowBlocks, mctinyV, McTinyPieceBytes)
import Control.Monad (foldM)
import Cookie (decodeCookie0)
import Data.ByteString qualified as BS
import Data.Vector.Fixed qualified as Fixed
import McTiny
import Nonce (Nonce (nonceSuffix))
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
    putStrLn $ "Ciphertext: " <> show ct
    putStrLn $ "Shared Secret: " <> show ss

    let initialState = Initial {ct = ct}

    runClient (Just "127.0.0.1") "4433" ss serverPK keypair initialState $ do
        putStrLn "Starting KEMTLS client Phase 0..."
        runPhase0

runPhase0 :: ClientM ()
runPhase0 = do
    -- generate 176 random binary bits || 0, 0 for Query0.random
    nonce <-
        Nonce.parseNonce
            <$> liftIO
                ( randomSized @NonceRandomPartBytes
                    <&> \r -> r `SizedBS.appendSized` Nonce.phase0C2SNonce
                )
    putStrLn $ "Generated Query0.random: " <> show nonce

    ct <- gets ct
    serverPK <- asks envServerPublicKey
    serverPKHash <- lift $ lift (publicKeyBytes serverPK >>= mctinyHash)
    putStrLn $ "Computed server public key hash: " <> show serverPKHash
    sendPacket $
        Query0
            { query0NonceR = nonce
            , query0ServerPKHash = serverPKHash
            , query0CipherText = ct
            , query0Extensions = []
            }

    putStrLn "Client initialized."

    packet <- readPacket @Reply0

    putStrLn $ "Received Reply0 packet: " <> show packet

    -- decode cookie
    let cookie = r0Cookie0 packet
    let longTermNonce = r0Nonce packet

    putStrLn $ "Stored Opaque Cookie (" <> show (SizedBS.sizedLength cookie) <> " bytes)"
    putStrLn "Handshake Phase 0 Complete."
    putStrLn $ "Long term nonce: " <> show (BS.unpack $ SizedBS.toStrictBS $ Nonce.fullNonce longTermNonce)

    guard (nonceSuffix longTermNonce == Nonce.phase0S2CNonce)

    put
        ( Phase1
            cookie
            (Nonce.randomPart longTermNonce)
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
            block <- liftIO $ publicKeyToMcTinyBlock pk rowPos colPos
            putStrLn $ "Requesting Block (" <> show rowPos <> "," <> show colPos <> ")"

            let packetNonce =
                    nonce `Nonce.withSuffix` Nonce.phase1C2SNonce rowPos colPos

            let queryPacket =
                    Query1
                        block
                        packetNonce
                        cookie

            sendPacket queryPacket

            receivedPacket <- readPacket @Reply1

            let reply1Nonce = r1Nonce receivedPacket

            unless (Nonce.nonceSuffix reply1Nonce == Nonce.phase1S2CNonce rowPos colPos) $
                error $
                    "Client Error: Invalid Reply Nonce for Block "
                        <> show (rowPos, colPos)

            let debugSeed = SizedBS.replicate @CookieSeedBytes 0xAA
            expectedSynd1 <- liftIO $ computePartialSyndrome debugSeed block colPos

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
    put (Phase2 cookie nonce blocks [])
    runPhase2 cookie

runPhase2 :: SizedByteString CookieC0Bytes -> ClientM ()
runPhase2 cookie0 = do
    putStrLn "Running Phase 2..."
    state <- get
    allCookies <- gets receivedBlocks
    for_ [1 .. ceiling (mcTinyRowBlocks / mctinyV)] $ \i -> do
        cookies <-
            forM [i * mctinyV - mctinyV + 1 .. i * mctinyV] $ \rowPos -> do
                forM [1 .. mcTinyColBlocks] $ \colPos -> do
                    case lookupBlock rowPos colPos allCookies of
                        Just block -> do 
                            putStrLn ("Query2: Using block (" <> show rowPos <> ", " <> show colPos <> ") for piece " <> show i)
                            pure block
                        Nothing -> error $ "Missing block (" <> show rowPos <> ", " <> show colPos <> ")"
        nonce <- gets longTermNonce
        let grid = Fixed.fromList' (map Fixed.fromList' cookies)
        let packet =
                Query2
                    { query2Cookies = grid
                    , query2Cookie0 = cookie0
                    , query2Nonce = nonce `Nonce.withSuffix` Nonce.phase2C2SNonce i
                    }
        sendPacket packet

        reply <- readPacket @Reply2

        let startRow = (i - 1) * mctinyV + 1
        let endRow   = i * mctinyV
        liftIO $ putStrLn $ "--- Verifying Piece " ++ show i ++ " (Rows " ++ show startRow ++ "-" ++ show endRow ++ ") ---"
        
        let debugSeed = SizedBS.replicate @CookieSeedBytes 0xAA
        -- 1. Re-calculate locally
        kp <- asks localKeypair
        
        -- IMPORTANT: Use the CORRECTED logic which mimics server aggregation
        expectedSynd2 <- liftIO $ calculatePieceLocally debugSeed i (publicKey kp)

        if r2Syndrome2 reply == expectedSynd2
            then liftIO $ putStrLn $ "MATCH: Piece " ++ show i ++ " is correct."
            else do
                liftIO $ putStrLn $ "MISMATCH at Piece " ++ show i
                liftIO $ putStrLn $ "  Expected: " ++ show expectedSynd2
                liftIO $ putStrLn $ "  Received: " ++ show (r2Syndrome2 reply)
                -- Optional: Crash here to stop
                error "Stopping due to syndrome mismatch."

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


calculatePieceLocally :: SizedByteString CookieSeedBytes -> Int -> McEliecePublicKey -> IO (SizedByteString McTinyPieceBytes)
calculatePieceLocally seed pieceIdx pk = do
    -- 1. Init Accumulator
    -- pieceIdx is 1-based. Wrapper 'computePieceSyndrome' expects 1-based (it subtracts 1).
    -- So we pass 'pieceIdx' directly.
    acc <- createPiece seed pieceIdx

    -- 2. Calculate Row Range
    let startRow = (pieceIdx - 1) * mctinyV + 1

    -- 3. Iterate Relative Rows 0..6
    foldM
        ( \currentAcc relRow -> do
            -- Calculate Absolute Row (1-based)
            let absRow = startRow + relRow

            -- Iterate Cols 0..7 (Relative) -> 1..8 (Absolute)
            foldM
                ( \innerAcc relCol -> do
                    let absCol = relCol + 1

                    -- Get Block (1-based)
                    blk <- publicKeyToMcTinyBlock pk absRow absCol
                    
                    -- Compute synd1 (1-based Col)
                    -- Wrapper 'computePartialSyndrome' expects 1-based Col (it subtracts 1).
                    s1 <- computePartialSyndrome seed blk absCol
                    putStrLn $ "Computed Partial Syndrome for Block (" <> show absRow <> "," <> show absCol <> "): " <> show s1

                    -- Absorb into Row 'relRow' (0-based)
                    putStrLn $ "  Absorbing Block (" <> show absRow <> "," <> show absCol <> ") into Piece " <> show pieceIdx <> ", Row " <> show relRow
                    absorbSyndromeIntoPiece innerAcc s1 (relRow + 1)
                )
                currentAcc
                [0 .. 7]
        )
        acc
        [0 .. 6]
