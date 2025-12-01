module Assertions where

import Control.Monad.Except

expect :: (MonadError e f) => Bool -> e -> f ()
expect True _ = pass
expect False errMsg = throwError errMsg

assertM :: (Applicative f) => Bool -> Text -> f ()
assertM condition errMsg =
    if condition
        then pass
        else error errMsg
