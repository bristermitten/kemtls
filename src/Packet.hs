{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE NoStarIsType #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Packet where

import Constants
import Data.Binary.Get (runGet)
import Data.Binary.Put
import Data.ByteString.Lazy qualified as LBS
import Data.Vector.Fixed qualified as Fixed
import Data.Vector.Fixed.Boxed (Vec)
import GHC.TypeLits (type (*), type (+))
import McTiny (SharedSecret, decryptPacketData, encryptPacketData)
import Nonce
import Packet.Generic
import SizedByteString as SizedBS
import Prelude hiding (ByteString, put, (||))

type NonceR = Nonce "R"

data Query1
    = Query1
    { q1Block :: SizedByteString McTinyBlockBytes -- 1kb chunk of the public key
    , q1Nonce :: NonceN -- N
    , q1Cookie0 :: SizedByteString CookieC0Bytes
    }
    deriving stock (Show)

instance KEMTLSPacket Query1 where
    type PacketSize Query1 = Query1Bytes
    type PacketPutContext Query1 = SharedSecret
    type PacketGetContext Query1 = SharedSecret
    type PacketGetResult Query1 = Query1
    putPacket ss (Query1 block nonce cookie) = do
        encrypted <- liftIO $ encryptPacketData block nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putSizedByteString cookie
            putNonce nonce

    getPacket ss input = do
        let (encryptedBlock, cookie, nonce) =
                flip runGet input $ do
                    encryptedBlock <- getSizedByteString @(McTinyBlockBytes + 16)
                    cookie <- getSizedByteString @CookieC0Bytes
                    nonce <- getNonce
                    pure (encryptedBlock, cookie, nonce)
        decryptedBlock <- liftIO $ decryptPacketData encryptedBlock nonce ss
        pure $
            Query1
                { q1Block = decryptedBlock
                , q1Nonce = nonce
                , q1Cookie0 = cookie
                }
type NonceN = Nonce "N"

data Reply1 = Reply1
    { r1Cookie0 :: SizedByteString CookieC0Bytes
    , r1Cookie1 :: SizedByteString Cookie1BlockBytes
    , r1Nonce :: NonceM
    }
    deriving stock (Show)

type NonceM = Nonce "M"

instance KEMTLSPacket Reply1 where
    type PacketSize Reply1 = Reply1Bytes
    type PacketPutContext Reply1 = SharedSecret
    type PacketGetContext Reply1 = SharedSecret
    type PacketGetResult Reply1 = Reply1

    putPacket ss (Reply1 cookie0 cookie1 nonce) = do
        let payload = cookie0 `appendSized` cookie1
        encrypted <- liftIO $ encryptPacketData payload nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putNonce nonce

    getPacket ss input = do
        let (encryptedPayload, nonce) =
                runGet
                    ( do
                        encryptedPayload <- getSizedByteString @(EncryptedSize (CookieC0Bytes + Cookie1BlockBytes))
                        nonce <- getNonce
                        pure (encryptedPayload, nonce)
                    )
                    input
        decryptedPayload <- liftIO $ decryptPacketData encryptedPayload nonce ss
        let (cookie0, cookie1) = SizedBS.splitAt @CookieC0Bytes decryptedPayload
        pure $
            Reply1
                { r1Cookie0 = cookie0
                , r1Cookie1 = cookie1
                , r1Nonce = nonce
                }

data Query2 = Query2
    { query2Cookies :: Query2CookieGrid
    , query2Cookie0 :: SizedByteString CookieC0Bytes
    , query2Nonce :: NonceN
    }
    deriving stock (Show)

-- 2D grid of cookies C_i,j
-- contains mctinyV (7) rows and mcTinyColBlocks (8) columns
type Query2CookieGrid =
    Vec McTinyV (Vec McTinyColBlocks (SizedByteString Cookie1BlockBytes))

-- query2Cookies should have this length i think
-- at least it does when testing but i'm not sure how consistent it is
-- it's derived from: C_iv−v+1,1,...,C_iv,l
type ExpectedQuery2CookieLength = McTinyColBlocks * McTinyV
expectedQuery2CookieLength :: Int
expectedQuery2CookieLength = mcTinyColBlocks * mctinyV

instance KEMTLSPacket Query2 where
    type PacketSize Query2 = Query2Bytes
    type PacketPutContext Query2 = SharedSecret
    type PacketGetContext Query2 = SharedSecret
    type PacketGetResult Query2 = Query2

    putPacket ss (Query2 cookies cookie0 nonce) = do
        let flattenedCookies = concatMap Fixed.toList (Fixed.toList cookies)

        let concatenatedCookies =
                mkSizedOrError @(ExpectedQuery2CookieLength * Cookie1BlockBytes) $
                    mconcat (fmap fromSized flattenedCookies)
        encrypted <- liftIO $ encryptPacketData concatenatedCookies nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putSizedByteString cookie0
            putNonce nonce

    getPacket ss input = do
        let (encryptedPayload, cookie0, nonce) =
                flip runGet input $ do
                    encryptedPayload <-
                        getSizedByteString
                            @( EncryptedSize
                                (ExpectedQuery2CookieLength * Cookie1BlockBytes)
                             )
                    cookie0 <- getSizedByteString @CookieC0Bytes
                    nonce <- getNonce
                    pure (encryptedPayload, cookie0, nonce)
        decryptedPayload <- liftIO $ decryptPacketData encryptedPayload nonce ss

        let flatCookies = SizedBS.splitInto @ExpectedQuery2CookieLength decryptedPayload
        let rowsList = chunksOf (natToNum @McTinyColBlocks) flatCookies
        let grid = Fixed.fromList' (map Fixed.fromList' rowsList) :: Query2CookieGrid
        pure $
            Query2
                { query2Cookies = grid
                , query2Cookie0 = cookie0
                , query2Nonce = nonce
                }
        where
            chunksOf :: Int -> [a] -> [[a]]
            chunksOf _ [] = []
            chunksOf n xs =
                let (h, t) = Prelude.splitAt n xs
                 in h : chunksOf n t

data Reply2 = Reply2
    { r2Cookie0 :: SizedByteString CookieC0Bytes
    , r2Syndrome2 :: SizedByteString McTinyPieceBytes
    , r2Nonce :: NonceM
    }
    deriving stock (Show)

instance KEMTLSPacket Reply2 where
    type PacketSize Reply2 = Reply2Bytes
    type PacketPutContext Reply2 = SharedSecret
    type PacketGetContext Reply2 = SharedSecret
    type PacketGetResult Reply2 = Reply2

    putPacket ss (Reply2 cookie0 r2Syndrome2 nonce) = do
        let payload = cookie0 || r2Syndrome2
        encrypted <- liftIO $ encryptPacketData payload nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putNonce nonce

    getPacket ss input = do
        let (encryptedPayload, nonce) =
                flip runGet input $ do
                    encryptedPayload <-
                        getSizedByteString
                            @( EncryptedSize
                                (CookieC0Bytes + McTinyPieceBytes)
                             )
                    nonce <- getNonce
                    pure (encryptedPayload, nonce)
        decryptedPayload <- liftIO $ decryptPacketData encryptedPayload nonce ss
        let (cookie0, cjs) = SizedBS.splitAt @CookieC0Bytes decryptedPayload

        pure $
            Reply2
                { r2Cookie0 = cookie0
                , r2Syndrome2 = cjs
                , r2Nonce = nonce
                }

data Query3 = Query3
    { query3MergedPieces :: SizedByteString McTinyColBytes
    , query3Nonce :: NonceN
    , query3Cookie0 :: SizedByteString CookieC0Bytes
    }
    deriving stock (Show)

instance KEMTLSPacket Query3 where
    type PacketSize Query3 = Query3Bytes
    type PacketPutContext Query3 = SharedSecret
    type PacketGetContext Query3 = SharedSecret
    type PacketGetResult Query3 = Query3

    putPacket ss (Query3 mergedPieces nonce cookie0) = do
        encrypted <- liftIO $ encryptPacketData mergedPieces nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putSizedByteString cookie0
            putNonce nonce

    getPacket ss input = do
        let (encryptedPayload, cookie0, nonce) =
                flip runGet input $ do
                    encryptedPayload <- getSizedByteString @(EncryptedSize McTinyColBytes)
                    cookie0 <- getSizedByteString @CookieC0Bytes
                    nonce <- getNonce
                    pure (encryptedPayload, cookie0, nonce)
        mergedPieces <- liftIO $ decryptPacketData encryptedPayload nonce ss
        pure $
            Query3
                { query3MergedPieces = mergedPieces
                , query3Nonce = nonce
                , query3Cookie0 = cookie0
                }

data Reply3 = Reply3
    { reply3C_z :: SizedByteString Cookie9Bytes
    -- ^ cookie C_z
    , reply3MergedPieces :: SizedByteString McTinyColBytes
    -- ^ merged pieces c_1, ..., c_r
    , reply3C :: SizedByteString HashBytes
    -- ^ hash value C
    , reply3Nonce :: NonceM
    -- ^ packet nonce M, 255, 255
    }
    deriving stock (Show)

instance KEMTLSPacket Reply3 where
    type PacketSize Reply3 = Reply3Bytes
    type PacketPutContext Reply3 = SharedSecret
    type PacketGetContext Reply3 = SharedSecret
    type PacketGetResult Reply3 = Reply3

    putPacket ss (Reply3 {..}) = do
        let payload = reply3C_z || reply3MergedPieces || reply3C
        encrypted <- liftIO $ encryptPacketData payload reply3Nonce ss
        pure $ runPut $ do
            putSizedByteString encrypted
            putNonce reply3Nonce

    getPacket ss input = do
        let (encryptedPayload, nonce) =
                flip runGet input $ do
                    encryptedPayload <-
                        getSizedByteString
                            @(EncryptedSize (Cookie9Bytes + McTinyColBytes + HashBytes))
                    nonce <- getSizedByteString @PacketNonceBytes
                    pure (encryptedPayload, parseNonce nonce)
        decryptedPayload <- liftIO $ decryptPacketData encryptedPayload nonce ss
        let (c_z, rest) = SizedBS.splitAt @Cookie9Bytes decryptedPayload
        let (mergedPieces, c) = SizedBS.splitAt @McTinyColBytes rest
        pure $
            Reply3
                { reply3C_z = c_z
                , reply3MergedPieces = mergedPieces
                , reply3C = c
                , reply3Nonce = nonce
                }
