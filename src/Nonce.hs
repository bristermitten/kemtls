{-# LANGUAGE RequiredTypeArguments #-}
{-# LANGUAGE TypeAbstractions #-}

{- | Wrapper types around Nonce values.
These are tagged with a type-level string tag to distinguish their usage in different protocol phases.
The tags used should match those described in the McTiny paper (eg R, M, N, etc).
-}
module Nonce where

import Constants (NonceRandomPartBytes, PacketNonceBytes)
import Data.Binary (Get, Put)
import Data.Binary.Put (putByteString)
import Data.ByteString (unpack)
import GHC.TypeLits
import SizedByteString (SizedByteString (..), SizedString (unsafeMkSized), appendSized, toStrictBS)
import SizedByteString qualified as SizedBS

{- | The random part of a Nonce, tagged with a type-level string.
Wraps a SizedByteString of length NonceRandomPartBytes.
-}
newtype NonceRandomPart (tag :: Symbol) = NonceRandomPart
    { getNonceRandomPart :: SizedByteString NonceRandomPartBytes
    }
    deriving stock (Eq, Show)

-- | A Nonce, consisting of a random part and a non-random suffix.
data Nonce (tag :: Symbol) = Nonce
    { randomPart :: NonceRandomPart tag
    , nonceSuffix :: SizedByteString 2
    }
    deriving stock (Eq, Show)

-- | Get the full Nonce as a SizedByteString of length PacketNonceBytes
fullNonce :: Nonce tag -> SizedByteString PacketNonceBytes
fullNonce (Nonce r s) = getNonceRandomPart r `appendSized` s

-- | Create a new Nonce by replacing the suffix of an existing Nonce
withSuffix :: NonceRandomPart tag -> SizedByteString 2 -> Nonce tag
withSuffix = Nonce

-- | Create a new Nonce by replacing the suffix of an existing Nonce
withNewSuffix :: Nonce tag -> SizedByteString 2 -> Nonce tag
withNewSuffix (Nonce r _) = Nonce r

-- | Parse a SizedByteString of length PacketNonceBytes into a Nonce
parseNonce :: SizedByteString PacketNonceBytes -> Nonce tag
parseNonce bs =
    let (r, s) = SizedBS.splitAt @NonceRandomPartBytes bs
     in Nonce (NonceRandomPart r) s

putNonce :: Nonce tag -> Put
putNonce nonce = putByteString (SizedBS.toStrictBS (fullNonce nonce))

getNonce :: Get (Nonce tag)
getNonce = do
    bs <- SizedBS.getSizedByteString @PacketNonceBytes
    pure (parseNonce bs)

{- | Nonce suffix for Client-to-Server messages in Phase 0
0, 0
-}
phase0C2SNonce :: SizedByteString 2
phase0C2SNonce = unsafeMkSized (fromList [0, 0])

{- | Nonce suffix for Server-to-Client messages in Phase 0
1, 0
-}
phase0S2CNonce :: SizedByteString 2
phase0S2CNonce = unsafeMkSized (fromList [1, 0])

{- | Nonce suffix for Client-to-Server messages in Phase 1
2(i-1), 64 + (j-1)
-}
phase1C2SNonce :: Int -> Int -> SizedByteString 2
phase1C2SNonce i j =
    unsafeMkSized
        ( fromList
            [ fromIntegral (2 * (i - 1))
            , fromIntegral (64 + j - 1)
            ]
        )

{- | Nonce suffix for Server-to-Client messages in Phase 1
2i - 1, 64 + (j-1)
-}
phase1S2CNonce :: Int -> Int -> SizedByteString 2
phase1S2CNonce i j =
    unsafeMkSized
        ( fromList
            [ fromIntegral (2 * i - 1)
            , fromIntegral (64 + j - 1)
            ]
        )

phase2C2SNonce :: Int -> SizedByteString 2
phase2C2SNonce i =
    unsafeMkSized
        ( fromList
            [ fromIntegral (2 * (i - 1))
            , 64 + 32
            ]
        )

decodePhase2C2SNonce :: SizedByteString 2 -> Maybe Int
decodePhase2C2SNonce bs =
    case unpack (toStrictBS bs) of
        [b1, b2] | b2 == 64 + 32 -> Just (fromIntegral (b1 `div` 2) + 1)
        _ -> Nothing

phase2S2CNonce :: Int -> SizedByteString 2
phase2S2CNonce i =
    unsafeMkSized
        ( fromList
            [ fromIntegral (2 * i - 1)
            , 64 + 32
            ]
        )

phase3C2SNonce :: SizedByteString 2
phase3C2SNonce = unsafeMkSized (fromList [254, 255])

phase3S2CNonce :: SizedByteString 2
phase3S2CNonce = unsafeMkSized (fromList [255, 255])

{- | Nonce suffix for all KEMTLS messages
since these packets will also have an outer TLS identifier
we can bundle them all together
-}
kemtlsNonceSuffix :: SizedByteString 2
kemtlsNonceSuffix = unsafeMkSized (fromList [255, 254])
