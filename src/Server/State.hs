module Server.State where

import Constants
import McTiny
import Network.Socket
import SizedByteString (SizedByteString)

-- | Main server state
data ServerState = ServerState
    { connectedClients :: [ClientInfo]
    -- ^ List of connected clients
    , serverSecretKey :: McElieceSecretKey
    -- ^ Long-term server secret key
    , cookieSecretKey :: SizedByteString CookieSecretKeyBytes
    -- ^ Ephemeral key for cookie encryption
    }

data ClientInfo = ClientInfo
    { clientId :: Int
    , clientSocket :: Socket
    , clientState :: ClientState
    , clientCookieMemory :: ClientCookies
    -- ^ Stores client cookies. Max size of 8 entries.
    }

-- | Stores cookies for a client. If we did cookie cycling this would be used.
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
    = -- | fresh connection, waiting for ClientHello to be sent
      Initialised
    | -- | Reply 0 sent, receiving Query1s
      McTinyPhase1 {ss_s :: SharedSecret}
    | -- | Reply 1 sent, receiving Query2s
      McTinyPhase2 {ss_s :: SharedSecret}
    | -- | Reply 2 sent, receiving Query3
      McTinyPhase3 {ss_s :: SharedSecret}
    | -- | McTiny handshake complete, finishing TLS handshake
      Completed {ss_s :: SharedSecret, ss_e :: SharedSecret}
    | -- | KEMTLS handshake complete, exchanging data
      ExchangingData {ss_s :: SharedSecret, ss_e :: SharedSecret}
    deriving stock (Show)
