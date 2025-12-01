-- procedures that both parties perform in KEMTLS
-- eg calling HKDF functions
module KEMTLS where

import Crypto.KDF.HKDF qualified as HKDF
import HKDF
import Transcript

kdf_dES :: (Monad m) => TranscriptT m ByteString
kdf_dES = do
    -- ES <- HKDF.Extract(0, 0)
    let _ES = HKDF.extract @_ @ByteString @ByteString "\x0" "\x0"
    -- dES <- HKDF.Expand(ES, "derived", ∅)
    expandLabelWithCurrentTranscript @ByteString _ES "derived"
