module Assertions where

import Control.Monad.Except

-- | Throw a checked error if the condition is False, otherwise do nothing.
expect :: (MonadError e f) => Bool -> e -> f ()
expect True _ = pass
expect False errMsg = throwError errMsg

-- | Throw an unchecked error if the condition is False, otherwise do nothing.
assertM :: (Applicative f, HasCallStack) => Bool -> Text -> f ()
assertM condition errMsg =
    if condition
        then pass
        else error errMsg
