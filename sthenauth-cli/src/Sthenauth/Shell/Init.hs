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

Special command that can bootstrap sthenauth from nothing.

-}
module Sthenauth.Shell.Init
  ( main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Exception.Safe (throwIO)
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Effect.Carrier
import Sthenauth.Providers.Local.Login
import Sthenauth.Shell.Byline
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.Options

--------------------------------------------------------------------------------
-- | Executed when the sthenauth subcommand is @init@.
main
  :: Environment
  -> Options a
  -> IO ()
main env opts
    = go
    & runLiftByline
    & runError >>= \case
        Left (e :: Sterr) -> throwIO e
        Right x           -> pure x
  where
    go = do
      creds <- getCredentials
      createInitialAdminAccount env creds >>=
        either throwError (const (pure ()))

    getCredentials =
      Credentials
        <$> (getEmail <$> maybeAskEmail (optionsEmail opts))
        <*> maybeAskPassword (optionsPassword opts)
