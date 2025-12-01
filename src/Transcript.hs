{-# LANGUAGE UndecidableInstances #-}

module Transcript where

import Constants (HashBytes)
import Crypto.Hash qualified as Crypto
import Crypto.MAC.HMAC qualified as HMAC
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Base16 qualified as Base16
import McTiny (SharedSecret)
import SizedByteString
import SizedByteString qualified as Sized

type HashAlgo = Crypto.SHA256

newtype TranscriptState = TranscriptState (Crypto.Context HashAlgo)

emptyTranscript :: TranscriptState
emptyTranscript = TranscriptState Crypto.hashInit

newtype TranscriptHash = TranscriptHash (Crypto.Digest HashAlgo)
    deriving newtype (Eq, Show, BA.ByteArrayAccess)

newtype TranscriptT m a = TranscriptT (StateT TranscriptState m a)
    deriving newtype (Functor, Applicative, Monad, MonadIO, MonadTrans, Alternative, MonadPlus)

instance (MonadState s m) => MonadState s (TranscriptT m) where
    get = lift get
    put = lift . put

instance (MonadReader r m) => MonadReader r (TranscriptT m) where
    ask = lift ask
    local f (TranscriptT m) = TranscriptT (local f m)

runTranscriptT :: (Monad m) => TranscriptT m a -> m a
runTranscriptT (TranscriptT action) = evalStateT action emptyTranscript

recordMessage :: (Monad m, MonadIO m) => BS.ByteString -> TranscriptT m ()
recordMessage bs = do
    -- 1. Perform the update
    TranscriptT $ modify (`hashUpdate` bs)

    -- 2. PEEK at the result for debugging
    -- We get the hash of the state *right now* without destroying the state
    (TranscriptHash currentDigest) <- getTranscriptHash

    let hexHash :: Text = decodeUtf8 (Base16.encode (BA.convert currentDigest))
    let chunkHex :: Text = decodeUtf8 (Base16.encode (BS.take 10 bs))
    let len = BS.length bs

    liftIO $ putTextLn $ "[TRANSCRIPT] Added " <> show len <> " bytes"
    liftIO $ putTextLn $ "    Chunk Start: " <> chunkHex <> "..."
    liftIO $ putTextLn $ "    Running Hash: " <> hexHash

getTranscriptHash :: (Monad m) => TranscriptT m TranscriptHash
getTranscriptHash = TranscriptT $ do
    TranscriptState ctx <- get
    let digest = Crypto.hashFinalize ctx :: Crypto.Digest HashAlgo
    return (TranscriptHash digest)

getTranscriptHMAC ::
    (Monad m) =>
    SharedSecret ->
    TranscriptT m (SizedByteString HashBytes)
getTranscriptHMAC key = do
    (TranscriptHash digest) <- getTranscriptHash
    let transcriptBytes = BA.convert digest :: BS.ByteString
    let keyBytes = Sized.toStrictBS key
    let hmac :: HMAC.HMAC HashAlgo = HMAC.hmac keyBytes transcriptBytes

    let hmacBytes = BA.convert hmac :: BS.ByteString

    return (mkSizedOrError $ toShort hmacBytes)

hashUpdate :: TranscriptState -> BS.ByteString -> TranscriptState
hashUpdate (TranscriptState ctx) bs = TranscriptState (Crypto.hashUpdate ctx bs)
