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
import Data.Time.Clock (getCurrentTime)
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Core.Session (ClearSessionKey(..))
import Sthenauth.Core.Site as Site
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Lang.Class
import Sthenauth.Lang.Script (MonadByline(..))
import Sthenauth.Providers.Local.Login
import qualified Sthenauth.Scripts as Scripts
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.Options as Options
import System.Console.Byline

--------------------------------------------------------------------------------
authenticate
  :: forall sig m a.
     ( MonadIO m
     , MonadByline m
     , MonadSthenauth m
     , Has Database sig m
     , Has Crypto sig m
     , Has (State CurrentUser) sig m
     , Has Error sig m
     )
  => Options a
  -> Site
  -> m CurrentUser
authenticate opts site = do
  rtime <- liftIO getCurrentTime
  case Options.session opts of
    Just key -> do
      user <- currentUserFromSessionKey site rtime (coerce key)
      put user
      pure user
    Nothing  -> do
      _ <- login ((,) <$> Options.email opts <*> Options.password opts)
      -- FIXME: Save an encrypted session key in ~/ and reload as necessary
      get

  where
    auth :: Text -> Text -> m ClearSessionKey
    auth e = fmap (^. _2) . liftSthenauth . Scripts.authenticate . Credentials e

    login :: Maybe (Text, Text) -> m ClearSessionKey
    login (Just (e, p)) = auth e p
    login Nothing       = do
      liftByline (sayLn ("Please authenticate..." <> fg green))
      e <- getEmail <$> maybeAskEmail (Options.email opts)
      p <- maybeAskPassword (Options.password opts)
      auth e p
