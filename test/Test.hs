{-# LANGUAGE TemplateHaskell #-}

module Test where

import Hedgehog
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import McTiny

main :: IO Bool
main =
    checkSequential $$discover

prop_mctiny_kem_works :: Property
prop_mctiny_kem_works = withTests 10 $ property $ do
    -- Generate a keypair
    kp <- evalIO generateKeypair

    annotate "Generated keypair"

    (ct, ss1) <- evalIO $ encapsulate (publicKey kp)

    ss2 <- evalIO $ decap (secretKey kp) ct
    annotate "Encapsulated and decapsulated shared secret"
    ss1 === ss2
