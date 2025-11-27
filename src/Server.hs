module Server where

import Control.Concurrent (forkFinally)
import Control.Exception qualified as E

import Control.Monad.Except (throwError)
import Crypto.Random
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put (runPut)
import Data.Bits
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import McTiny (McElieceSecretKey, decap, decryptPacketData)
import Network.Socket
import Network.Socket.ByteString.Lazy
import Network.Transport.Internal (decodeNum16)
import Packet
import Utils

kemtlsServer :: Maybe HostName -> ServiceName -> McElieceSecretKey -> IO ()
kemtlsServer mhost port serverSecretKey = do
  addr <- resolve

  vacuous $ E.bracket (open addr) close loop
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

    loop sock = infinitely $
      E.bracketOnError (accept sock) (close . fst) $
        \(conn, _peer) ->
          void $
            -- 'forkFinally' alone is unlikely to fail thus leaking @conn@,
            -- but 'E.bracketOnError' above will be necessary if some
            -- non-atomic setups (e.g. spawning a subprocess to handle
            -- @conn@) before proper cleanup of @conn@ is your case
            forkFinally (server conn) (const $ gracefulClose conn 5000)

    server conn = do
      putStrLn "Client connected"
      do
        p <- runExceptT $ do
          encryptedExtensions <- liftIO $ recv conn (512 + 16)
          expect (not $ LBS.null encryptedExtensions) "Failed to read extensions from client"
          putStrLn "Received valid MAC and extensions from client"
          pkHash <- liftIO $ recv conn 32
          expect (LBS.length pkHash == 32) "Failed to read public key hash from client"
          ct <- liftIO $ recv conn 226
          expect (LBS.length ct == 226) "Failed to read ciphertext from client"
          nonce <- liftIO $ recv conn 24
          expect (LBS.length nonce == 24) "Failed to read nonce from client"
          expect (nonce `LBS.index` 22 == 0 && nonce `LBS.index` 23 == 0) "Invalid nonce received from client"

          s <- liftIO $ decap serverSecretKey (fromLazy ct)
          putStrLn $ "Decapsulated shared secret: " ++ show s

          extensions <- liftIO $ decryptPacketData (fromLazy encryptedExtensions) (fromLazy nonce) s
          putStrLn $ "Decrypted extensions: " ++ show extensions
          -- assert that extensions are 512 zero bytes
          expect (extensions == BS.replicate 512 0) "Invalid extensions received from client"

          drg <- liftIO getSystemDRG
          -- generate 176 random binary bits || 0, 0 for ClientHello.random
          let (randomBytes :: ByteString, drg') = withRandomBytes drg (176 `div` 8) $ \bs ->
                bs <> BS.pack [0, 0] -- last 2 bytes zeroed
          putStrLn $ "Generated Reply0.random: " ++ show randomBytes

          -- generate 32 byte seed
          let (seed :: ByteString, drg'') = withRandomBytes drg' 32 id

          putStrLn $ "Generated Reply0.seed: " ++ show seed

        case p of
          Left err -> putStrLn $ "Failed to parse Query: " ++ show err
          Right ch -> do
            putStrLn $ "Received Query: " ++ show ch

expect :: Bool -> Text -> ExceptT Text IO ()
expect True _ = pass
expect False errMsg = throwError errMsg

sendPacket :: forall a. (TLSRecord a) => Socket -> a -> IO ()
sendPacket sock pkt = do
  let payload = runPut (Data.Binary.put pkt)
      len = fromIntegral (LBS.length payload) :: Word16
      header =
        "\x16"
          <> "\x03\x01" -- Handshake type
          <> encodeNum16 len -- TLS 1.3
          -- Length
  sendAll sock (header <> payload)
