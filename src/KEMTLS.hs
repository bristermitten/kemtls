-- procedures that both parties perform in KEMTLS
-- eg calling HKDF functions
module KEMTLS where

import Crypto.KDF.HKDF qualified as HKDF
import HKDF
import McTiny
import SizedByteString (mkSizedOrError)
import SizedByteString qualified as Sized
import Transcript

derive_dES :: (Monad m) => SharedSecret -> TranscriptT m ByteString
derive_dES ss_s = do
    let _ES = HKDF.extract @_ @ByteString @ByteString "\x0" (Sized.toStrictBS ss_s)
    expandLabelWithCurrentTranscript @ByteString _ES "derived"

{- | Derive the handshake traffic secrets CHTS and SHTS
Note that unlike in the KEMTLS spec, these are derived from ss_s rather than ss_e
since we don't know ss_e yet due to McTiny's flow
-}
deriveHandshakeSecret :: forall m. (Monad m) => SharedSecret -> TranscriptT m (SharedSecret, SharedSecret)
deriveHandshakeSecret ss_s = do
    dES <- derive_dES ss_s

    let _HS = HKDF.extract @_ @ByteString @ByteString dES (Sized.toStrictBS ss_s)
    chts <- expandLabelWithCurrentTranscript @ByteString _HS "c hs traffic"
    shts <- expandLabelWithCurrentTranscript @ByteString _HS "s hs traffic"

    pure (mkSizedOrError $ toShort chts, mkSizedOrError $ toShort shts)
