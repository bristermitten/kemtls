module ServerMain where

import McTiny
import Paths (pathToServerSecretKey)
import Server (kemtlsServer)

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    hSetBuffering stderr LineBuffering
    serverSK <- readSecretKey pathToServerSecretKey
    putStrLn $ "Loaded server secret key from " <> pathToServerSecretKey

    kemtlsServer (Just "0.0.0.0") "4433" serverSK
