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
import Sthenauth.Core.Action (MonadByline(..))
import qualified Sthenauth.Core.AuthN as A
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Core.HTTP
import Sthenauth.Core.Remote (Remote, requestTime)
import Sthenauth.Core.Session (ClearSessionKey(..))
import Sthenauth.Core.Site as Site
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Providers.Local.Login
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.Options as Options
import System.Console.Byline
import Web.Cookie (setCookieValue)

--------------------------------------------------------------------------------
authenticate
  :: forall sig m a.
     ( MonadIO m
     , MonadByline m
     , Has Database sig m
     , Has Crypto sig m
     , Has HTTP sig m
     , Has (State CurrentUser) sig m
     , Has Error sig m
     , MonadRandom m
     )
  => Options a
  -> Site
  -> Remote
  -> m CurrentUser
authenticate opts site remote =
  case Options.session opts of
    Just key -> do
      user <- currentUserFromSessionKey site (remote ^. requestTime) (coerce key)
      put user
      pure user
    Nothing  -> do
      _ <- login ((,) <$> Options.email opts <*> Options.password opts)
      -- FIXME: Save an encrypted session key in ~/ and reload as necessary
      get

  where
    auth :: Text -> Text -> m ClearSessionKey
    auth n p = A.requestAuthN site remote
      (A.LoginWithLocalCredentials (Credentials n p)) >>= \case
        (Just c, A.LoggedIn _) -> pure (ClearSessionKey $ decodeUtf8 $ setCookieValue c)
        _ -> throwUserError (AuthenticationFailedError Nothing)

    login :: Maybe (Text, Text) -> m ClearSessionKey
    login (Just (e, p)) = auth e p
    login Nothing       = do
      liftByline (sayLn ("Please authenticate..." <> fg green))
      e <- getEmail <$> maybeAskEmail (Options.email opts)
      p <- maybeAskPassword (Options.password opts)
      auth e p
