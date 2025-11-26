module Main where

import Main.Utf8 qualified as Utf8
import McTiny
import Server (kemtlsServer)

data Example = Example
  { name :: Text
  , age :: Int
  }
  deriving stock (Show, Eq)

{- |
 Main entry point.

 `just run` will invoke this function.
-}
main :: IO ()
main = do
  -- For withUtf8, see https://serokell.io/blog/haskell-with-utf8
  Utf8.withUtf8 $ do
    kp <- generateKeypair
    print kp

    (ct, ss) <- encapsulate (publicKey kp)
    putStrLn $ "Ciphertext: " ++ show ct
    putStrLn $ "Shared Secret: " ++ show ss

    ss' <- decap (secretKey kp) ct
    putStrLn $ "Decapsulated Shared Secret: " ++ show ss'
    putStrLn $ "Shared secrets match: " ++ show (ss == ss')

    kemtlsServer Nothing "4433"
