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
module Sthenauth.Shell.AuthN
  ( authenticate
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Sthenauth.Effect
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Core.Session (ClearSessionKey(..))
import Sthenauth.Shell.Byline
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.Options
import System.Console.Byline

--------------------------------------------------------------------------------
-- | Authenticate the current user.
authenticate
  :: forall sig m a.
     ( MonadIO m
     , Has LiftByline    sig m
     , Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => Options a
  -> m ()
authenticate opts =
  case optionsSession opts of
    Just key -> setCurrentUser (coerce key) $> ()
    Nothing  ->
      login ((,) <$> optionsEmail opts <*> optionsPassword opts)
      -- FIXME: Save an encrypted session key in ~/ and reload as necessary

  where
    login :: Maybe (Text, Text) -> m ()
    login (Just (e, p)) = loginWithCredentials (Credentials e p) $> ()
    login Nothing       = do
      liftByline (sayLn ("Please authenticate..." <> fg green))
      e <- getEmail <$> maybeAskEmail (optionsEmail opts)
      p <- maybeAskPassword (optionsPassword opts)
      loginWithCredentials (Credentials e p) $> ()
