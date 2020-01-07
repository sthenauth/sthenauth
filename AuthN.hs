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
-- Library Imports:
import System.Console.Byline

--------------------------------------------------------------------------------
-- Project Imports:
import qualified Sthenauth.Core.AuthN as Core
import Sthenauth.Lang.Class
import qualified Sthenauth.Scripts.AuthN as Scripts
import Sthenauth.Shell.Byline
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.Options as Options
import Sthenauth.Tables.Session (ClearSessionKey(..))
import Sthenauth.Tables.Site as Site
import Sthenauth.Types

--------------------------------------------------------------------------------
authenticate
  :: forall m s r k e a .
     ( MonadIO m
     , MonadByline m
     , MonadSthenauth m
     , MonadDB m
     , MonadCrypto k m
     , MonadError e m
     , AsError e
     , MonadState s m
     , HasCurrentUser s
     , MonadReader r m
     , HasSecrets r k
     , MaybeHasSite r
     , HasRemote r
     )
  => Options a
  -> m CurrentUser
authenticate opts =
  case Options.session opts of
    Just key -> Core.resumeSession (coerce key)
    Nothing  -> do
      _ <- login ((,) <$> Options.email opts <*> Options.password opts)
      -- liftByline $ sayLn ("Your session key is: " <> text (coerce key))
      use currentUser

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
