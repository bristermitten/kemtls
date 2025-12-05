{-# LANGUAGE UndecidableInstances #-}

{- | Implements the KEMTLS transcript mechanism, maintaining a running hash of all messages exchanged
during the handshake. This is used to derive keys and ensure integrity of the handshake.
-}
module Transcript where

import Constants (HashBytes)
import Crypto.Hash qualified as Crypto
import Crypto.MAC.HMAC qualified as HMAC
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import McTiny (SharedSecret)
import SizedByteString
import SizedByteString qualified as Sized

-- | The hash algorithm used for the transcript
type HashAlgo = Crypto.SHA256

-- | Represents the state of the transcript, which is essentially a running hash context
newtype TranscriptState = TranscriptState (Crypto.Context HashAlgo)

emptyTranscript :: TranscriptState
emptyTranscript = TranscriptState Crypto.hashInit

newtype TranscriptHash = TranscriptHash (Crypto.Digest HashAlgo)
    deriving newtype (Eq, Show, BA.ByteArrayAccess)

-- | Monad transformer for managing the transcript state
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

-- | Record a message into the transcript by updating the running hash
recordMessage :: (Monad m, MonadIO m) => BS.ByteString -> TranscriptT m ()
recordMessage bs = do
    TranscriptT $ modify (`hashUpdate` bs)

-- | Get the current transcript hash
getTranscriptHash :: (Monad m) => TranscriptT m TranscriptHash
getTranscriptHash = TranscriptT $ do
    TranscriptState ctx <- get
    let digest = Crypto.hashFinalize ctx :: Crypto.Digest HashAlgo
    return (TranscriptHash digest)

-- | Get an HMAC of the current transcript hash using the provided key
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
