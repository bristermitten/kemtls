module ClientMain where

import Client (closeClient, kemtlsClient, sendPacket)
import Control.Exception qualified as E
import Crypto.Random
import Data.ByteString qualified as BS
import McTiny
import Packet (McTinyC2SPacket (..))
import Paths

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

  drg <- getSystemDRG
  -- generate 176 random binary bits || 0, 0 for ClientHello.random
  let (randomBytes :: ByteString, _) = withRandomBytes drg (176 `div` 8) $ \bs ->
        bs <> BS.pack [0, 0] -- last 2 bytes zeroed
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
