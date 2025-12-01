{- | Unused mctiny code that implements the original phase0
left as a reference
-}
module McTinyArchive where

-- | Server processing

-- processQuery0 :: ExceptT Text ConnectionM ()
-- processQuery0 = do
--     client <- lift (lift Prelude.get)
--     let conn = clientSocket client

--     stateVar <- lift ask
--     globalState <- liftIO $ readMVar stateVar

--     (query0, ss) <- lift $ Protocol.recvPacket @Query0 conn globalState
--     print query0

--     -- generate 32 byte seed
--     seed <- liftIO $ randomSized @CookieSeedBytes
--     putStrLn $ "Generated Reply0.seed: " <> show seed

--     (cookie, nonce) <- liftIO $ createCookie0 (cookieSecretKey globalState) ss seed 0

--     let packet =
--             Reply0
--                 { r0Cookie0 = cookie
--                 , r0Nonce = nonce
--                 }

--     liftIO $ sendPacket client ss packet

--     setClientState (SentReply0 ss)

-- data Reply0 = Reply0
--     { r0Cookie0 :: SizedByteString CookieC0Bytes
--     -- ^ cookie C_0
--     , r0Nonce :: NonceN
--     -- ^ packet nonce M, 1, 0
--     }
--     deriving stock (Show)

-- instance KEMTLSPacket Reply0 where
--     type PacketSize Reply0 = Reply0Bytes
--     type PacketPutContext Reply0 = SharedSecret
--     type PacketGetContext Reply0 = SharedSecret
--     type PacketGetResult Reply0 = Reply0
--     putPacket ss (Reply0 cookie nonce) = do
--         encrypted <- liftIO $ encryptPacketData cookie nonce ss
--         pure $ runPut $ do
--             putSizedByteString encrypted
--             putNonce nonce

--     getPacket ss input = do
--         let (encryptedCookie, nonce) =
--                 runGet
--                     ( do
--                         encryptedCookie <- getSizedByteString @(CookieC0Bytes + 16)
--                         nonce <- getNonce
--                         pure (encryptedCookie, nonce)
--                     )
--                     input
--         decryptedCookie <- liftIO $ decryptPacketData encryptedCookie nonce ss

--         pure $
--             Reply0
--                 { r0Cookie0 = decryptedCookie
--                 , r0Nonce = nonce
--                 }

-- | packet code

-- data Query0
--     = Query0
--     { query0NonceR :: NonceR -- R from the paper
--     , query0ServerPKHash :: SizedByteString HashBytes -- sha3 hash of server's static public key
--     , query0CipherText :: Ciphertext -- encapsulation of server's static key
--     , query0Extensions :: [SizedByteString 0] -- currently unused, should be empty
--     }
--     deriving stock (Show)

-- instance McTinyPacket Query0 where
--     type PacketSize Query0 = Query0Bytes

--     type PacketPutContext Query0 = SharedSecret
--     type PacketGetContext Query0 = ServerState
--     type PacketGetResult Query0 = (Query0, SharedSecret)
--     putPacket ss (Query0 nonce pkHash ct exts) = do
--         guard (null exts) -- no extensions supported
--         -- 512 0 bytes for extensions gets sent encrypted
--         encrypted <- liftIO $ encryptPacketData (SizedBS.replicate @PacketExtensionsBytes 0) nonce ss
--         pure $ runPut $ do
--             putSizedByteString encrypted
--             putSizedByteString pkHash
--             putSizedByteString ct
--             putNonce nonce

--     getPacket serverState input = do
--         let (mac, encrypted, pkHash, ct, nonce) =
--                 flip runGet input $ do
--                     mac <- getSizedByteString @16
--                     encrypted <- getSizedByteString @PacketExtensionsBytes
--                     pkHash <- getSizedByteString @HashBytes
--                     ct <- getSizedByteString @CiphertextBytes
--                     nonce <- getNonce
--                     pure (mac, encrypted, pkHash, ct, nonce)

--         -- make sure last 2 bytes of nonce are zero
--         guard (nonceSuffix nonce == phase0C2SNonce)

--         ss <- liftIO $ decap (serverSecretKey serverState) ct
--         decryptedExtensions <- liftIO $ decryptPacketData (mac `SizedBS.appendSized` encrypted) nonce ss
--         -- assert that extensions are 512 zero bytes
--         guard (decryptedExtensions == SizedBS.replicate @PacketExtensionsBytes 0)

--         pure
--             ( Query0
--                 { query0NonceR = nonce
--                 , query0ServerPKHash = pkHash
--                 , query0CipherText = ct
--                 , query0Extensions = [] -- no extensions supported
--                 }
--             , ss
--             )

-- | client code

-- runPhase0 :: ClientM ()
-- runPhase0 = do
--     -- generate 176 random binary bits || 0, 0 for Query0.random
--     nonce <-
--         Nonce.parseNonce
--             <$> liftIO
--                 ( randomSized @NonceRandomPartBytes
--                     <&> \r -> r `SizedBS.appendSized` Nonce.phase0C2SNonce
--                 )
--     putStrLn $ "Generated Query0.random: " <> show nonce

--     ct <- gets ct
--     serverPK <- asks envServerPublicKey
--     serverPKBytes <- liftIO (publicKeyBytes serverPK)
--     serverPKHash <- liftIO (mctinyHash serverPKBytes)
--     putStrLn $ "Computed server public key hash: " <> show serverPKHash
--     sendPacket $
--         Query0
--             { query0NonceR = nonce
--             , query0ServerPKHash = serverPKHash
--             , query0CipherText = ct
--             , query0Extensions = []
--             }

--     putStrLn "Client initialized."

--     packet <- readPacket @Reply0

--     putStrLn $ "Received Reply0 packet: " <> show packet

--     -- decode cookie
--     let cookie = r0Cookie0 packet
--     let longTermNonce = r0Nonce packet

--     putStrLn $ "Stored Opaque Cookie (" <> show (SizedBS.sizedLength cookie) <> " bytes)"
--     putStrLn "Handshake Phase 0 Complete."
--     putStrLn $ "Long term nonce: " <> show (BS.unpack $ SizedBS.toStrictBS $ Nonce.fullNonce longTermNonce)

--     guard (nonceSuffix longTermNonce == Nonce.phase0S2CNonce)

--     put
--         ( Phase1
--             cookie
--             (Nonce.randomPart longTermNonce)
--             emptyReceivedBlocks
--         )
--     runPhase1
