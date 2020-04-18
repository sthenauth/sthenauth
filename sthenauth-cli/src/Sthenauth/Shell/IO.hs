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
  ( dieOnSigTerm
  , shellIO
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Concurrent (myThreadId)
import Control.Exception.Safe (try, throwTo)
import Sthenauth.Core.Error
import System.Exit (ExitCode(..))
import System.Signal

--------------------------------------------------------------------------------
-- | Ensure the main thread is killed when receiving SIGTERM, similar
-- to how SIGINT works.
dieOnSigTerm :: IO ()
dieOnSigTerm = do
  tid <- myThreadId
  installHandler sigTERM (const $ throwTo tid ExitSuccess)

--------------------------------------------------------------------------------
-- | Run an IO action, catching synchronous exceptions.
shellIO :: (MonadIO m, Has (Throw Sterr) sig m) => IO a -> m a
shellIO = liftIO . try >=> either (throwError . ShellException) pure
