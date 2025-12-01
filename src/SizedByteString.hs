{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

module SizedByteString where

import Crypto.Random (MonadRandom, getRandomBytes)
import Data.Binary (Binary)
import Data.Binary.Get (Get, getByteString)
import Data.Binary.Put (Put, putByteString)
import Data.ByteArray (ByteArrayAccess)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BS (create, createUptoN')
import Data.ByteString.Lazy qualified as LBS
import Data.ByteString.Short qualified as SBS
import Data.Type.Ord (type (<), type (<=))
import Foreign (Ptr, callocBytes, fillBytes)
import Foreign.C (CString)
import GHC.TypeLits (Div, Mod, type (+), type (-))

newtype SizedByteString (n :: Nat) = SizedByteString {getSized :: SBS.ShortByteString}
    deriving newtype (Eq, Show, Binary, Ord)

newtype SizedLazyByteString (n :: Nat) = SizedLazyByteString {getSizedLazy :: LBS.ByteString}
    deriving newtype (Eq, Show, Binary)

class ByteStringLike t where
    toByteString :: t -> BS.ByteString
    fromByteString :: BS.ByteString -> t
    bsLength :: t -> Int
    bsReplicate :: Int64 -> Word8 -> t
    bsAtIndex :: t -> Int -> Word8
    bsTake :: Int -> t -> t
    bsSplitAt :: Int -> t -> (t, t)

instance ByteStringLike BS.ByteString where
    toByteString = id
    fromByteString = id
    bsLength = BS.length
    bsReplicate len = BS.replicate (fromIntegral len)
    bsAtIndex = BS.index
    bsTake = BS.take
    bsSplitAt = BS.splitAt

instance ByteStringLike SBS.ShortByteString where
    toByteString = fromShort
    fromByteString = toShort
    bsLength = SBS.length
    bsReplicate len w = toShort (BS.replicate (fromIntegral len) w)
    bsAtIndex = SBS.index
    bsTake n sbs =
        toShort (BS.take n (fromShort sbs))
    bsSplitAt n sbs =
        let (a, b) = BS.splitAt n (fromShort sbs)
         in (toShort a, toShort b)

instance ByteStringLike LBS.ByteString where
    toByteString = toStrict
    fromByteString = fromStrict
    bsLength = fromIntegral . LBS.length
    bsReplicate = LBS.replicate
    bsAtIndex lbs i = LBS.index lbs (fromIntegral i)
    bsTake n = LBS.take (fromIntegral n)
    bsSplitAt n = LBS.splitAt (fromIntegral n)

-- =========================================================================
-- SIZED STRING INTERFACE
-- =========================================================================

class (ByteStringLike (Impl t)) => SizedString t (n :: Nat) where
    type Impl t

    sizedLength :: t n -> (KnownNat n) => Int
    sizedLength _ = natToNum @n

    fromSized :: t n -> Impl t
    unsafeMkSized :: Impl t -> t n

    snocSized :: t n -> Word8 -> t (n + 1)
    appendSized :: t n -> t m -> t (n + m)

    (||) :: t n -> t m -> t (n + m)
    (||) = appendSized

    mkSized :: (KnownNat n) => Impl t -> Maybe (t n)
    mkSized bs
        | bsLength bs == natToNum @n = Just (unsafeMkSized bs)
        | otherwise = Nothing

instance SizedString SizedByteString n where
    type Impl SizedByteString = SBS.ShortByteString

    fromSized (SizedByteString sbs) = sbs

    snocSized (SizedByteString sbs) b =
        SizedByteString (toShort $ BS.snoc (fromShort sbs) b)

    appendSized (SizedByteString s1) (SizedByteString s2) =
        SizedByteString (toShort $ BS.append (fromShort s1) (fromShort s2))

    unsafeMkSized = SizedByteString

-- Instance for the Lazy wrapper
instance SizedString SizedLazyByteString n where
    type Impl SizedLazyByteString = LBS.ByteString
    fromSized (SizedLazyByteString lbs) = lbs
    snocSized (SizedLazyByteString lbs) b = SizedLazyByteString (lbs `LBS.snoc` b)
    appendSized (SizedLazyByteString lbs) (SizedLazyByteString lbs') = SizedLazyByteString (lbs `LBS.append` lbs')
    unsafeMkSized = SizedLazyByteString

toStrictBS :: SizedByteString n -> BS.ByteString
toStrictBS (SizedByteString sbs) = fromShort sbs

lazyToStrict :: SizedLazyByteString n -> SizedByteString n
lazyToStrict (SizedLazyByteString lbs) = SizedByteString (toShort (toStrict lbs))

strictToLazy :: SizedByteString n -> SizedLazyByteString n
strictToLazy (SizedByteString sbs) = SizedLazyByteString (fromStrict (fromShort sbs))

unsafeSized :: BS.ByteString -> SizedByteString n
unsafeSized bs = SizedByteString (toShort bs)

randomSized :: forall n m. (KnownNat n, MonadRandom m) => m (SizedByteString n)
randomSized = do
    let len = fromIntegral (natVal (Proxy @n))
    bs <- getRandomBytes len
    return $ SizedByteString (toShort bs)

index :: forall i n t. (KnownNat i, KnownNat n, i < n, SizedString t n) => t n -> Word8
index sized = bsAtIndex (fromSized sized) (natToNum @i)

take :: forall m n t. (KnownNat m, m <= n, SizedString t n, SizedString t m) => t n -> t m
take sized =
    let bs = fromSized sized
        len = natToNum @m @Int
     in unsafeMkSized (bsTake len bs)

drop :: forall m n t. (KnownNat m, m <= n, SizedString t n, SizedString t (n - m)) => t n -> t (n - m)
drop sized =
    let bs = fromSized sized
        len = natToNum @m @Int
     in unsafeMkSized (snd (bsSplitAt len bs))

splitAt :: forall m n t. (KnownNat m, KnownNat n, m <= n, SizedString t n, SizedString t m, SizedString t (n - m)) => t n -> (t m, t (n - m))
splitAt sized =
    let bs = fromSized sized
        len = natToNum @m @Int
        (bs1, bs2) = bsSplitAt len bs
     in (unsafeMkSized bs1, unsafeMkSized bs2)

splitInto ::
    forall k n t.
    ( KnownNat k
    , KnownNat n
    , n `Mod` k ~ 0
    , SizedString t n
    , SizedString t (n `Div` k)
    , KnownNat (Div n k)
    ) =>
    t n -> [t (n `Div` k)]
splitInto sized =
    let bs = fromSized sized
        partLen = natToNum @(n `Div` k) @Int
        go bStr
            | bsLength bStr == 0 = []
            | otherwise =
                let (partBs, restBs) = bsSplitAt partLen bStr
                 in unsafeMkSized partBs : go restBs
     in go bs

natToNum :: forall n num. (KnownNat n, Num num) => num
natToNum = fromIntegral (natVal (Proxy @n))

replicate :: forall n t. (KnownNat n, SizedString t n) => Word8 -> t n
replicate b =
    let len = natToNum @n @Int
     in unsafeMkSized (bsReplicate (fromIntegral len) b)

mkSizedOrError :: forall n t. (KnownNat n, SizedString t n, HasCallStack) => Impl t -> t n
mkSizedOrError bs =
    case mkSized bs of
        Just sized -> sized
        Nothing -> error $ "Incorrect length for SizedByteString: expected " <> show expectedLen <> ", got " <> show (bsLength bs)
    where
        expectedLen = natVal (Proxy @n)

putSizedByteString :: (SizedString t n) => t n -> Put
putSizedByteString sized = putByteString (toByteString (fromSized sized))

getSizedByteString :: forall n. (KnownNat n) => Get (SizedByteString n)
getSizedByteString = do
    let len = natToNum @n @Int
    bs <- getByteString len
    case mkSized (toShort bs) of
        Just sized -> pure sized
        Nothing -> fail $ "Failed to get SizedByteString of length " <> show len

-- IO and FFI functions

create :: forall n. (KnownNat n) => (Ptr Word8 -> IO ()) -> IO (SizedByteString n)
create action = do
    let size = natToNum @n @Int
    let action' ptr = do
            -- zero out memory
            fillBytes ptr (fromIntegral size) 0
            action ptr
    bs <- BS.create size action'
    pure (unsafeSized bs)

createWith :: forall n r. (KnownNat n) => (Ptr Word8 -> IO r) -> IO (SizedByteString n, r)
createWith action = do
    let size = natToNum @n @Int
    let action' ptr = do
            -- zero out memory
            fillBytes ptr (fromIntegral size) 0
            r <- action ptr
            pure (size, r)
    bsAndResult <- BS.createUptoN' size action'
    let (bs, result) = bsAndResult
    pure (unsafeSized bs, result)

useAsCString :: forall n a. (KnownNat n) => SizedByteString n -> (CString -> IO a) -> IO a
useAsCString (SizedByteString sbs) action = do
    let bs = fromShort sbs
    BS.useAsCString bs action

useAsCStringLen :: forall n a. (KnownNat n) => SizedByteString n -> ((CString, Int) -> IO a) -> IO a
useAsCStringLen (SizedByteString sbs) action = do
    let bs = fromShort sbs
    BS.useAsCStringLen bs action
