module ServerMain where

import Main.Utf8 qualified as Utf8
import McTiny
import Paths (pathToServerSecretKey)
import Server (kemtlsServer)

main :: IO ()
main = do
    serverSK <- readSecretKey pathToServerSecretKey
    putStrLn $ "Loaded server secret key from " <> pathToServerSecretKey

    kemtlsServer (Just "127.0.0.1") "4433" serverSK
