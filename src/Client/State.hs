module Client.State where

import Constants
import SizedByteString

data ClientState
    = Initial
    | ReceivedReply0
        { cookie :: SizedByteString CookieC0Bytes
        , longTermNonce :: SizedByteString PacketNonceBytes
        }
