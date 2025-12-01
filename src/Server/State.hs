module Server.State where

import Constants
import McTiny
import Network.Socket
import SizedByteString (SizedByteString)

data ServerState = ServerState
    { connectedClients :: [ClientInfo]
    , serverSecretKey :: McElieceSecretKey
    , cookieSecretKey :: SizedByteString CookieSecretKeyBytes -- Ephemeral key for cookie encryption
    }

data ClientInfo = ClientInfo
    { clientId :: Int
    , clientSocket :: Socket
    , clientState :: ClientState
    , clientCookieMemory :: ClientCookies
    -- ^ Stores client cookies. Max size of 8 entries.
    }

data ClientCookies = ClientCookies
    { cookieMap :: IntMap ClientCookie
    , activeCookieId :: Int
    }

emptyClientCookies :: ClientCookies
emptyClientCookies = ClientCookies mempty 0

data ClientCookie = ClientCookie
    { cookieKey :: ByteString
    , cookieTimestamp :: Int64
    , remainingUses :: Int
    }

data ClientState
    = -- | waiting for ClientHello
      Initialised
    | -- | Reply 0 sent, receiving Query1s
      SentReply0 {ss_s :: SharedSecret}
    | SentReply1 {ss_s :: SharedSecret}
    | Phase3 {ss_s :: SharedSecret}
    | Completed {ss_s :: SharedSecret, ss_e :: SharedSecret}
    deriving stock (Show)
