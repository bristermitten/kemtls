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
    = Initialised
    | SentReply0 SharedSecret
    deriving stock (Show)
