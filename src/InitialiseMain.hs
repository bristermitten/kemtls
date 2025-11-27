module InitialiseMain where

import Data.ByteString qualified as BS
import Foreign
import McTiny
import Paths
import System.Directory (createDirectoryIfMissing)

{- | Initialises the static keypair for the server, saving it to disk.
This emulates the functionality where the client knows the server's public key in advance.
-}
main :: IO ()
main = do
  putStrLn "Initialising server keypair..."
  createDirectoryIfMissing True pathToServerKeypair

  kp <- generateKeypair
  saveKeypair kp

saveKeypair :: (MonadIO m) => McElieceKeypair -> m ()
saveKeypair kp = liftIO $ do
  let pubPath = pathToServerPublicKey
  let secPath = pathToServerSecretKey
  withForeignPtr (publicKey kp) $ \pkPtr -> do
    pkBS <- BS.packCStringLen (castPtr pkPtr, pkBytes)
    writeFileBS pubPath pkBS
    putStrLn $ "Saved public key to " <> pubPath

  withForeignPtr (secretKey kp) $ \skPtr -> do
    skBS <- BS.packCStringLen (castPtr skPtr, skBytes)
    writeFileBS secPath skBS
    putStrLn $ "Saved secret key to " <> secPath
