{-# LANGUAGE AllowAmbiguousTypes #-}

module SizedByteString where

import Crypto.Random
import Data.Binary
import Data.Binary.Get (getByteString)
import Data.Binary.Put
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Type.Ord (type (<), type (<=))
import GHC.TypeLits (type (+))

newtype SizedByteString (n :: Nat) = SizedByteString {getSized :: BS.ByteString}
    deriving newtype (Eq, Show, Binary)

newtype SizedLazyByteString (n :: Nat) = SizedLazyByteString {getSizedLazy :: LBS.ByteString}
    deriving newtype (Eq, Show, Binary)

lazyToStrict :: SizedLazyByteString n -> SizedByteString n
lazyToStrict (SizedLazyByteString lbs) = SizedByteString (toStrict lbs)

strictToLazy :: SizedByteString n -> SizedLazyByteString n
strictToLazy (SizedByteString bs) = SizedLazyByteString (fromStrict bs)

unsafeSized :: BS.ByteString -> SizedByteString n
unsafeSized = SizedByteString

randomSized :: forall n m. (KnownNat n, MonadRandom m) => m (SizedByteString n)
randomSized = do
    let len = fromIntegral (natVal (Proxy @n))
    bs <- getRandomBytes len
    return $ SizedByteString bs

-- randomSizedLazy :: forall n m. (KnownNat n, MonadRandom m) => m (SizedLazyByteString n)
-- randomSizedLazy = do
--     let len = fromIntegral (natVal (Proxy @n))
--     bs <- getRandomBytes len
--     return $ SizedLazyByteString bs

class ByteStringLike t where
    toByteString :: t -> BS.ByteString
    fromByteString :: BS.ByteString -> t
    bsLength :: t -> Int

    bsReplicate :: Int64 -> Word8 -> t
    bsAtIndex :: t -> Int -> Word8

    bsTake :: Int -> t -> t

instance ByteStringLike BS.ByteString where
    toByteString = id
    fromByteString = id
    bsLength = BS.length
    bsReplicate len = BS.replicate (fromIntegral len)
    bsAtIndex = BS.index
    bsTake = BS.take
instance ByteStringLike LBS.ByteString where
    toByteString = toStrict
    fromByteString = fromStrict
    bsLength = fromIntegral . LBS.length
    bsReplicate = LBS.replicate
    bsAtIndex lbs i = LBS.index lbs (fromIntegral i)
    bsTake n = LBS.take (fromIntegral n)

class (ByteStringLike (Impl t)) => SizedString t (n :: Nat) where
    type Impl t

    sizedLength :: t n -> (KnownNat n) => Int
    sizedLength _ = natToNum @n

    fromSized :: t n -> Impl t
    unsafeMkSized :: Impl t -> t n

    snocSized :: t n -> Word8 -> t (n + 1)
    appendSized :: t n -> t m -> t (n + m)

    mkSized :: (KnownNat n) => Impl t -> Maybe (t n)
    mkSized bs
        | bsLength bs == natToNum @n = Just (unsafeMkSized bs)
        | otherwise = Nothing

instance SizedString SizedByteString n where
    type Impl SizedByteString = BS.ByteString

    fromSized (SizedByteString bs) = bs
    snocSized (SizedByteString bs) b = SizedByteString (BS.snoc bs b)
    appendSized (SizedByteString bs) (SizedByteString bs') = SizedByteString (bs `BS.append` bs')

    unsafeMkSized = SizedByteString

instance SizedString SizedLazyByteString n where
    type Impl SizedLazyByteString = LBS.ByteString
    fromSized (SizedLazyByteString lbs) = lbs
    snocSized (SizedLazyByteString lbs) b = SizedLazyByteString (lbs `LBS.snoc` b)
    appendSized (SizedLazyByteString lbs) (SizedLazyByteString lbs') = SizedLazyByteString (lbs `LBS.append` lbs')
    unsafeMkSized = SizedLazyByteString

index :: forall i n t. (KnownNat i, KnownNat n, i < n, SizedString t n) => t n -> Word8
index sized = bsAtIndex (fromSized sized) (natToNum @i)

take :: forall m n t. (KnownNat m, m <= n, SizedString t n, SizedString t m) => t n -> t m
take sized =
    let bs = fromSized sized
        len = natToNum @m @Int
     in unsafeMkSized (bsTake len bs)

natToNum :: forall n num. (KnownNat n, Num num) => num
natToNum = fromIntegral (natVal (Proxy @n))

replicate :: forall n t. (KnownNat n, SizedString t n) => Word8 -> t n
replicate b = unsafeMkSized (bsReplicate (natToNum @n @Int64) b)

mkSizedOrError :: forall n t. (KnownNat n, SizedString t n) => Impl t -> t n
mkSizedOrError bs =
    case mkSized bs of
        Just sized -> sized
        Nothing -> error $ "ByteString has incorrect length for SizedByteString: expected " <> show expectedLen <> ", got " <> show (bsLength bs)
    where
        expectedLen = natVal (Proxy @n)

putSizedByteString :: (SizedString t n) => t n -> Put
putSizedByteString sized = putByteString (toByteString (fromSized sized))

getSizedByteString :: forall n. (KnownNat n) => Get (SizedByteString n)
getSizedByteString = do
    let len = natToNum @n @Int
    bs <- getByteString len
    case mkSized bs of
        Just sized -> pure sized
        Nothing -> fail $ "Failed to get SizedByteString of length " <> show len
