module Nonce where

import Data.ByteString (pack, unpack)
import SizedByteString (SizedByteString (..), SizedString (unsafeMkSized), toStrictBS)

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
