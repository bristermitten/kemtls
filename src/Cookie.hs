module Cookie where

import Constants
import GHC.TypeLits
import McTiny
import Nonce qualified
import SizedByteString as SizedBS

{- | create the first cookie packet field
corresponds to 'C0 <- (AE(S,E :N,1,0 : hash(s_m)),b)'  in the paper
-}
createCookie0 ::
    -- | server cookie key (s_m)
    SizedByteString CookieSecretKeyBytes ->
    -- | shared secret key (S)
    SharedSecret ->
    -- | seed (E)
    SizedByteString CookieSeedBytes ->
    -- | key id (0-7)
    Word8 ->
    -- | encoded cookie data
    IO (SizedByteString CookieC0Bytes, SizedByteString PacketNonceBytes)
createCookie0 kCookie kMaster seed keyId = do
    encKey <- mctinyHash (fromSized kCookie) -- hash(s_m)
    nonce <-
        randomSized @NonceRandomPartBytes
            <&> \r -> r `SizedBS.appendSized` Nonce.phase0S2CNonce
    let payload = kMaster `appendSized` seed -- S, E
    encrypted <- encryptPacketData payload nonce encKey -- AE(S,E : N,1,0, hash(s_m))
    return
        ( encrypted `snocSized` keyId -- b
        , nonce
        )

-- | decode the first cookie packet field
decodeCookie0 ::
    -- | server cookie key (s_m)
    SizedByteString CookieSecretKeyBytes ->
    -- | encoded cookie data
    SizedByteString CookieC0Bytes ->
    -- | packet nonce
    SizedByteString PacketNonceBytes ->
    -- | decoded shared secret (S) and seed (E)
    IO (SharedSecret, SizedByteString CookieSeedBytes)
decodeCookie0 kCookie cookieC0 packetNonce = do
    -- we have C0 ← (AE(S,E : N,1,0 : hash(sm)),m mod 8)
    let (encData, _keyIdBS) = SizedBS.splitAt @(CookieC0Bytes - 1) cookieC0
    let baseNonce = SizedBS.take @22 packetNonce
        cookieNonce = baseNonce `SizedBS.appendSized` Nonce.phase0S2CNonce

    encKey <- mctinyHash (fromSized kCookie) -- hash(s_m)
    decrypted <- decryptPacketData encData cookieNonce encKey -- DAE(...)
    let (sharedSecretBS, seedBS) = SizedBS.splitAt @SharedSecretBytes decrypted
    return (sharedSecretBS, seedBS)

{- | Create a phase 1 cookie
Ci,j ← (AE(ci,j : N,2i−1,64+j−1 : s), m mod 8)
-}
createCookie1 ::
    SizedByteString CookieSecretKeyBytes ->
    SizedByteString McTinySyndromeBytes -> -- syndrome ci,j
    SizedByteString PacketNonceBytes -> -- N
    Int -> -- i (row)
    Int -> -- j (column)
    Word8 -> -- key id (m)
    IO (SizedByteString Cookie1BlockBytes, SizedByteString PacketNonceBytes)
createCookie1 kCookie syndrome packetNonce row col keyId = do
    encKey <- mctinyHash (fromSized kCookie)

    let baseNonce = SizedBS.take @22 packetNonce
        cookieNonce =
            baseNonce
                `SizedBS.appendSized` Nonce.phase1S2CNonce row col

    encrypted <- encryptPacketData syndrome cookieNonce encKey

    return (encrypted `snocSized` keyId, cookieNonce)

decodeCookie1 ::
    -- | server cookie key (s_m)
    SizedByteString CookieSecretKeyBytes ->
    -- | encoded cookie data
    SizedByteString Cookie1BlockBytes ->
    -- | packet nonce
    SizedByteString PacketNonceBytes ->
    Int -> -- i (row)
    Int -> -- j (column)

    -- | decoded syndrome ci,j and nonce M
    IO (SizedByteString McTinySyndromeBytes, SizedByteString PacketNonceBytes)
decodeCookie1 kCookie cookie1 packetNonce i j = do
    let (encData, _keyIdBS) = SizedBS.splitAt @(Cookie1BlockBytes - 1) cookie1
    let baseNonce = SizedBS.take @22 packetNonce
        cookieNonce = baseNonce `SizedBS.appendSized` Nonce.phase1S2CNonce i j
    encKey <- mctinyHash (fromSized kCookie)
    decrypted <- decryptPacketData encData cookieNonce encKey
    return (decrypted, cookieNonce)
