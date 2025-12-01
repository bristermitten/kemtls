-- | Wrapper around crypton's HKDF to make the usage more akin to how the KEMTLS paper describes it
module HKDF where

import Crypto.Hash
import Crypto.KDF.HKDF
import Crypto.KDF.HKDF qualified as HKDF
import Data.Binary (putWord8)
import Data.Binary.Put (putByteString, putWord16be, runPut)
import Data.ByteArray qualified as BA
import Data.ByteString qualified as B
import Transcript

type HKDFHashAlgorithm = SHA384

{-
	// CAHTS <- HKDF.Expand(AHS, "c ahs traffic", CH..CKC)
	clientSecret := hs.suite.deriveSecret(ahs,
		clientAuthenticatedHandshakeTrafficLabel, hs.transcript)

func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
-}

{- | HKDF-expand that implements
Derive-Secret from RFC 8446, Section 7.1:


       HKDF-Expand-Label(Secret, Label, Context, Length) =
            HKDF-Expand(Secret, HkdfLabel, Length)

       Where HkdfLabel is specified as:

       struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;

       Derive-Secret(Secret, Label, Messages) =
            HKDF-Expand-Label(Secret, Label,
                              Transcript-Hash(Messages), Hash.length)
-}
expandLabel ::
    forall out.
    (BA.ByteArray out) =>
    PRK HKDFHashAlgorithm ->
    -- | label
    ByteString ->
    -- | context string
    ByteString ->
    out
expandLabel prk label contextStr = do
    let hashLength = hashDigestSize (error "hash algorithm" :: HKDFHashAlgorithm)
    let realLabel = runPut $ do
            -- Length
            putWord16be (fromIntegral hashLength)

            -- Label
            let fullLabel = "tls13 " <> label
            putWord8 (fromIntegral (B.length fullLabel))
            putByteString fullLabel

            -- Context
            let ctxHashBS = contextStr
            putWord8 (fromIntegral (B.length ctxHashBS))
            putByteString ctxHashBS

    let okm = HKDF.expand prk (fromLazy realLabel) hashLength
    okm

expandLabelWithCurrentTranscript ::
    forall out m.
    (BA.ByteArray out, Monad m) =>
    PRK HKDFHashAlgorithm ->
    ByteString ->
    TranscriptT m out
expandLabelWithCurrentTranscript prk label = do
    (TranscriptHash digest) <- getTranscriptHash

    let context = BA.convert digest
    let okm = expandLabel @out prk label context
    return okm
