-- procedures that both parties perform in KEMTLS
-- eg calling HKDF functions
module KEMTLS where

import Crypto.KDF.HKDF qualified as HKDF
import Data.ByteString qualified as BS
import HKDF
import McTiny
import SizedByteString (mkSizedOrError)
import SizedByteString qualified as Sized
import Transcript

deriveEarlySecret :: (Monad m) => SharedSecret -> TranscriptT m ByteString
deriveEarlySecret ss_s = do
    -- ES <- HKDF.Extract(∅, ss_s)
    let _ES =
            HKDF.extract
                (BS.pack (replicate 32 0))
                (Sized.toStrictBS ss_s)
    -- dES <- HKDF.Expand(ES, "derived", ∅)
    pure $ expandLabel _ES "derived" ""

{- | Derive the handshake traffic secrets CHTS and SHTS
Note that unlike in the KEMTLS spec, these are derived from ss_s rather than ss_e
since we don't know ss_e yet due to McTiny's flow.

As ss_e is already in dES, this adds no new entropy but is slightly more faithful compared
to e.g. using another 0 string
-}
deriveHandshakeSecret :: forall m. (Monad m) => SharedSecret -> TranscriptT m (SharedSecret, SharedSecret)
deriveHandshakeSecret ss_s = do
    dES <- deriveEarlySecret ss_s

    let _HS = HKDF.extract @_ @ByteString @ByteString dES (Sized.toStrictBS ss_s)
    chts <- expandLabelWithCurrentTranscript @ByteString _HS "c hs traffic"
    shts <- expandLabelWithCurrentTranscript @ByteString _HS "s hs traffic"

    pure (mkSizedOrError $ toShort chts, mkSizedOrError $ toShort shts)

deriveMasterSecret ::
    forall m.
    (Monad m) =>
    -- | ss_s
    SharedSecret ->
    -- | ss_e
    SharedSecret ->
    TranscriptT m (SharedSecret, SharedSecret)
deriveMasterSecret ss_s ss_e = do
    dES <- deriveEarlySecret ss_s
    let _HS = HKDF.extract @_ @ByteString @ByteString dES (Sized.toStrictBS ss_e)

    let dHS = expandLabel @ByteString _HS "derived" ""

    let _MS = HKDF.extract @_ @ByteString @ByteString dHS (Sized.toStrictBS ss_e)

    fk_c <- expandLabelWithCurrentTranscript @ByteString _MS "c finished"
    fk_s <- expandLabelWithCurrentTranscript @ByteString _MS "s finished"

    pure
        ( mkSizedOrError $ toShort fk_c
        , mkSizedOrError $ toShort fk_s
        )
