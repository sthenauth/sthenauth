{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    git://code.devalot.com/sthenauth.git

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

Temporary: To be removed after a new version of Byline is released.

-}
module Sthenauth.Shell.Byline
  ( MonadByline(..)
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import System.Console.Byline

--------------------------------------------------------------------------------
-- Package Imports:
import Sthenauth.Lang.Script
import Sthenauth.Types.Error

--------------------------------------------------------------------------------
class (Monad m) => MonadByline m where
  liftByline :: Byline IO a -> m a

  -- FIXME:  A real MonadByline would have the following methods:
  -- puts :: Text -> m ()
  -- prompt :: Text -> m Text
  -- etc.

instance MonadByline Script where
  liftByline b = liftIO (runByline b) >>= \case
    Nothing -> throwing _RuntimeError "unexpected termination"
    Just x  -> return x
