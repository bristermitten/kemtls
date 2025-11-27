module Client.State where

import Constants
import McTiny (Ciphertext)
import SizedByteString

data ClientState
    = Initial
        { ct :: Ciphertext
        -- ^ Ciphertext from ENC(pk)
        }
    | ReceivedReply0
        { cookie :: SizedByteString CookieC0Bytes
        , longTermNonce :: SizedByteString PacketNonceBytes
        }
