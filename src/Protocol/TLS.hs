module Protocol.TLS where

import Constants (kemTLSMcTinyVersion)
import Data.Binary qualified
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Network.Socket
import Network.Socket.ByteString
import Packet.TLS
import Protocol (recvExact)
import Transcript (TranscriptT)
import Transcript qualified

recvTLSRecord ::
    forall a m.
    ( MonadIO m
    , Alternative m
    , TLSRecord a
    , HasCallStack
    , MonadPlus m
    ) =>
    Socket -> TranscriptT m a
recvTLSRecord sock = do
    let recordType = 0x16 -- Handshake

    -- Read record header
    recType <- liftIO $ recv sock 1
    putStrLn $ "Received record type: " <> show recType
    ver <- liftIO $ recvExact sock 2
    putStrLn $ "Received version bytes: " <> show ver
    lenBytes <- liftIO $ recvExact sock 2
    putStrLn $ "Received length bytes: " <> show lenBytes

    guard (recType == BS.pack [recordType])
    guard (runGet getWord16be ver == kemTLSMcTinyVersion)

    let len = fromIntegral (runGet getWord16be lenBytes)
    putStrLn $ "Parsed length: " <> show len
    recordData <- liftIO (recvExact sock len)
    Transcript.recordMessage (fromLazy recordData)
    pure $ runGet (Data.Binary.get @a) recordData

sendTLSRecord :: forall a m. (TLSRecord a, MonadIO m) => Socket -> a -> TranscriptT m ()
sendTLSRecord sock record = do
    let recordType = 0x16 -- Handshake
    let version = kemTLSMcTinyVersion -- KEMTLS v1.0
    let body = Data.Binary.encode record
    Transcript.recordMessage (fromLazy body)
    let len = fromIntegral (LBS.length body) :: Word16
    let header = runPut $ do
            putWord8 recordType
            putWord16be version
            putWord16be len

    let packetData = header `LBS.append` body
    liftIO $ sendAll sock (fromLazy packetData)
