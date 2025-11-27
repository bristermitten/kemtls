module Paths where

pathToServerKeypair :: FilePath
pathToServerKeypair = "state/server_keypair"

pathToServerPublicKey :: FilePath
pathToServerPublicKey = pathToServerKeypair <> "/public.key"

pathToServerSecretKey :: FilePath
pathToServerSecretKey = pathToServerKeypair <> "/secret.key"
