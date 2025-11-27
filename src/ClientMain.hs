module ClientMain where

import Client (closeClient, kemtlsClient, recvPacket, sendPacket)
import Control.Exception qualified as E
import McTiny
import Packet
import Paths
import SizedByteString
import SizedByteString qualified as SizedBS

main :: IO ()
main = do
    kp <- generateKeypair
    print kp

    -- load server's public key
    serverPK <- readPublicKey pathToServerPublicKey
    putStrLn $ "Loaded server public key from " <> pathToServerPublicKey

    -- encapsulate a shared secret
    (ct, ss) <- encapsulate serverPK
    putStrLn $ "Ciphertext: " ++ show ct
    putStrLn $ "Shared Secret: " ++ show ss

    -- generate 176 random binary bits || 0, 0 for ClientHello.random
    randomBytes :: SizedByteString 24 <- randomSized @22 >>= \s -> pure (s `snocSized` 0 `snocSized` 0)
    putStrLn $ "Generated Query0.random: " ++ show randomBytes

    hash <- mctinyHash =<< publicKeyBytes serverPK
    putStrLn $ "Computed server public key hash: " ++ show hash
    E.bracket (kemtlsClient (Just "127.0.0.1") "4433" ss) closeClient $ \client -> do
        sendPacket client $
            Query0
                { query0Nonce = randomBytes
                , query0ServerPKHash = hash
                , query0CipherText = ct
                , query0Extensions = []
                }

        putStrLn "Client initialized."

        packet <- recvPacket @Reply0 client

        putStrLn $ "Received Reply0 packet: " ++ show packet

        -- decode cookie
        let cookie = r0Cookie0 packet
        let longTermNonce = r0Nonce packet

        putStrLn $ "Stored Opaque Cookie (" ++ show (SizedBS.sizedLength cookie) ++ " bytes)"
        putStrLn "Handshake Phase 0 Complete."
        putStrLn $ "Long term nonce: " ++ show longTermNonce

        guard (SizedBS.index @22 longTermNonce == 1 && SizedBS.index @23 longTermNonce == 0)
