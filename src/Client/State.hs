module Client.State where

import Constants
import Data.Map.Strict qualified as Map
import McTiny (Ciphertext, McElieceKeypair, SharedSecret)
import Nonce (NonceRandomPart)
import Packet (NonceN)
import SizedByteString

data ClientState
    = Initial
        { ct :: Ciphertext
        -- ^ Ciphertext from ENC(pk)
        }
    | -- | We have received Reply0 from the server and are now in phase1 receiving Reply1s
      Phase1
        { cookie0 :: SizedByteString CookieC0Bytes
        , longTermNonce :: NonceRandomPart "N"
        -- ^ N from Reply0
        , receivedBlocks :: ReceivedBlocks
        -- ^ List of C_i,j
        , chts :: SharedSecret
        -- ^ Derived CHTS from ss_s. Strictly this is just a cache as we can always re-derive it
        , shts :: SharedSecret
        -- ^ Derived SHTS from ss_s
        }
    | Phase2
        { cookie0 :: SizedByteString CookieC0Bytes
        , longTermNonce :: NonceRandomPart "N"
        , receivedBlocks :: ReceivedBlocks
        , syndromes :: [SizedByteString McTinyPieceBytes]
        , chts :: SharedSecret
        -- ^ Derived CHTS from ss_s. Strictly this is just a cache as we can always re-derive it
        , shts :: SharedSecret
        -- ^ Derived SHTS from ss_s
        }
    deriving stock (Show)

newtype ReceivedBlocks = ReceivedBlocks
    {blocks :: Map (Int, Int) (SizedByteString Cookie1BlockBytes)}
    deriving stock (Show)

emptyReceivedBlocks :: ReceivedBlocks
emptyReceivedBlocks = ReceivedBlocks mempty

addBlock :: Int -> Int -> SizedByteString Cookie1BlockBytes -> ReceivedBlocks -> ReceivedBlocks
addBlock row col block (ReceivedBlocks bm) =
    ReceivedBlocks (Map.insert (row, col) block bm)

lookupBlock :: Int -> Int -> ReceivedBlocks -> Maybe (SizedByteString Cookie1BlockBytes)
lookupBlock row col (ReceivedBlocks bm) =
    Map.lookup (row, col) bm
