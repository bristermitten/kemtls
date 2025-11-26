module Server where

import Control.Concurrent (forkFinally)
import Control.Exception qualified as E

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put (runPut)
import Data.Bits
import Data.ByteString.Lazy qualified as LBS
import Network.Socket
import Network.Socket.ByteString.Lazy
import Network.Transport.Internal (decodeNum16)
import Packet
import Control.Monad.Except (throwError)

kemtlsServer :: Maybe HostName -> ServiceName -> IO ()
kemtlsServer mhost port = do
  addr <- resolve

  vacuous $ E.bracket (open addr) close loop
  where
    resolve = do
      let hints =
            defaultHints
              { addrFlags = [AI_PASSIVE]
              , addrSocketType = Stream
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

      p <- acceptPacket @ClientHello conn

      case p of
        Left err -> putStrLn $ "Failed to parse ClientHello" ++ show err
        Right ch -> do
          putStrLn $ "Received ClientHello: " ++ show ch
          -- Echo back the same ClientHello for demonstration
          pass

-- read a TLS packet
acceptPacket :: forall a. (TLSRecord a) => Socket -> IO (Either Text a)
acceptPacket sock = runExceptT $ do
  -- a <- lift $ recv sock 3
  -- error $ "Received data: " <> decodeUtf8 a
  contentType <- lift $ recv sock 1
  expect (contentType == "\x16") ("Invalid Handshake:" <> decodeUtf8 contentType) -- Handshake type
  version <- lift $ recv sock 2
  expect (version == "\x03\x01") "Invalid Version" -- TLS 1.3
  lenBs <- lift $ recv sock 2
  let len = decodeNum16 (fromLazy lenBs)
  payload <- lift $ recv sock len
  pure $ runGet (Data.Binary.get @a) payload

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

encodeNum16 :: Word16 -> LBS.ByteString
encodeNum16 w =
  LBS.pack [fromIntegral (w `shiftR` 8), fromIntegral w]
