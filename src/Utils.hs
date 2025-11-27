module Utils where

import Data.Bits
import Data.ByteString.Lazy qualified as LBS

-- | Encode a 24-bit big-endian integer as a lazy ByteString
encodeNum24 :: Word32 -> LBS.ByteString
encodeNum24 w =
  LBS.pack [fromIntegral (w `shiftR` 16), fromIntegral (w `shiftR` 8), fromIntegral w]

encodeNum16 :: Word16 -> LBS.ByteString
encodeNum16 w =
  LBS.pack [fromIntegral (w `shiftR` 8), fromIntegral w]
