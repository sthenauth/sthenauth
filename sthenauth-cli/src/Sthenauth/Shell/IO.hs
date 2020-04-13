{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    https://code.devalot.com/sthenauth/sthenauth

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

-}
module Sthenauth.Shell.IO
  ( shellIO
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Exception.Safe (try)
import Sthenauth.Core.Error

--------------------------------------------------------------------------------
-- | Run an IO action, catching synchronous exceptions.
shellIO :: (MonadIO m, Has Error sig m) => IO a -> m a
shellIO action = do
  result <- liftIO (try action)

  case result of
    Left e  -> throwError (ShellException e)
    Right a -> pure a
