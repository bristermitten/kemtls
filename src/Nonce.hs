module Nonce where

import Data.ByteString (pack)
import SizedByteString (SizedByteString (..))

{- | Nonce suffix for Client-to-Server messages in Phase 0
0, 0
-}
phase0C2SNonce :: SizedByteString 2
phase0C2SNonce = SizedByteString (pack [0, 0])

{- | Nonce suffix for Server-to-Client messages in Phase 0
1, 0
-}
phase0S2CNonce :: SizedByteString 2
phase0S2CNonce = SizedByteString (pack [1, 0])

{- | Nonce suffix for Client-to-Server messages in Phase 1
2(i-1), 64 + (j-1)
-}
phase1C2SNonce :: Int -> Int -> SizedByteString 2
phase1C2SNonce i j =
    SizedByteString
        ( pack
            [ fromIntegral (2 * (i - 1))
            , fromIntegral (64 + j - 1)
            ]
        )

{- | Nonce suffix for Server-to-Client messages in Phase 1
2i - 1, 64 + (j-1)
-}
phase1S2CNonce :: Int -> Int -> SizedByteString 2
phase1S2CNonce i j =
    SizedByteString
        ( pack
            [ fromIntegral (2 * i - 1)
            , fromIntegral (64 + j - 1)
            ]
        )
