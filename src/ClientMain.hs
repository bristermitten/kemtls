module ClientMain where

import Client
import Client.State
import Constants (NonceRandomPartBytes, mcTinyColBlocks, mcTinyRowBlocks)
import Data.ByteString qualified as BS
import McTiny
import Nonce qualified
import Packet
import Paths
import SizedByteString
import SizedByteString qualified as SizedBS

main :: IO ()
main = do
    -- load server's public key
    serverPK <- readPublicKey pathToServerPublicKey
    putStrLn $ "Loaded server public key from " <> pathToServerPublicKey

    -- encapsulate a shared secret
    (ct, ss) <- encapsulate serverPK
    putStrLn $ "Ciphertext: " ++ show ct
    putStrLn $ "Shared Secret: " ++ show ss

    let initialState = Initial {ct = ct}

    runClient (Just "127.0.0.1") "4433" ss serverPK initialState $ do
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

    serverPK <- asks envServerPublicKey
    ct <- gets ct
    hash <- lift $ lift (mctinyHash =<< publicKeyBytes serverPK)
    putStrLn $ "Computed server public key hash: " ++ show hash
    sendPacket $
        Query0
            { query0Nonce = nonce
            , query0ServerPKHash = hash
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
    put (ReceivedReply0 cookie longTermNonce)
    runPhase1

runPhase1 :: ClientM ()
runPhase1 = do
    -- Placeholder for Phase 1 implementation
    liftIO $ putStrLn "Running Phase 1..."
    pk <- asks envServerPublicKey

    cookie <- gets cookie
    nonce <- gets longTermNonce

    for_ [1 .. mcTinyRowBlocks] $ \rowPos -> do
        for_ [1 .. mcTinyColBlocks] $ \colPos -> do
            liftIO $ putStrLn $ "Processing block (" ++ show rowPos ++ ", " ++ show colPos ++ ")"
            block <- liftIO $ pk2Block pk rowPos colPos

            let packetNonce =
                    SizedBS.take @22 nonce
                        `SizedBS.appendSized` Nonce.phase1C2SNonce rowPos colPos

            let suffix = BS.drop 22 (fromSized packetNonce)
            liftIO $ putStrLn $ "Client sending nonce: " ++ show (BS.unpack (fromSized packetNonce))
            liftIO $ putStrLn $ "Client sending nonce Suffix: " ++ show suffix
            let queryPacket =
                    Query1
                        block
                        packetNonce
                        cookie

            sendPacket queryPacket
            receivedPacket <- readPacket @Reply1
            let reply1Nonce = r1Nonce receivedPacket
            let rRowByte = SizedBS.index @22 reply1Nonce
            let rColByte = SizedBS.index @23 reply1Nonce
            let expectedRowByte = fromIntegral (2 * rowPos - 1) :: Word8
            let expectedColByte = fromIntegral (64 + colPos - 1) :: Word8
            unless (rRowByte == expectedRowByte && rColByte == expectedColByte) $
                error $
                    "Client Error: Invalid Reply Nonce for Block "
                        <> show (rowPos, colPos)
                        <> ". Expected "
                        <> show [expectedRowByte, expectedColByte]
                        <> " but got "
                        <> show [rRowByte, rColByte]

            liftIO $ putStrLn $ "Received Reply1 packet: " ++ show receivedPacket
