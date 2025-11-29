module Client.State where

import Constants
import Data.Map.Strict qualified as Map
import McTiny (Ciphertext)
import SizedByteString

data ClientState
    = Initial
        { ct :: Ciphertext
        -- ^ Ciphertext from ENC(pk)
        }
    | -- | We have received Reply0 from the server and are now in phase1 receiving Reply1s
      ReceivedReply0
        { cookie :: SizedByteString CookieC0Bytes
        , longTermNonce :: SizedByteString NonceRandomPartBytes
        -- ^ N from Reply0
        , receivedBlocks :: ReceivedBlocks
        -- ^ List of C_i,j
        }

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
