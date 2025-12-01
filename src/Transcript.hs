{-# LANGUAGE UndecidableInstances #-}

module Transcript where

import Crypto.Hash qualified as Crypto
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS

type HashAlgo = Crypto.SHA384

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

recordMessage :: (Monad m) => BS.ByteString -> TranscriptT m ()
recordMessage bs = TranscriptT $ modify (`hashUpdate` bs)

getTranscriptHash :: (Monad m) => TranscriptT m TranscriptHash
getTranscriptHash = TranscriptT $ do
    TranscriptState ctx <- get
    let digest = Crypto.hashFinalize ctx :: Crypto.Digest HashAlgo
    return (TranscriptHash digest)

hashUpdate :: TranscriptState -> BS.ByteString -> TranscriptState
hashUpdate (TranscriptState ctx) bs = TranscriptState (Crypto.hashUpdate ctx bs)
