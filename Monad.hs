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
module Sthenauth.API.Monad
  ( runRequest
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Servant.Server

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.API.Log
import Sthenauth.API.Middleware (Client)
import Sthenauth.Lang.Script
import Sthenauth.Lang.Class
import Sthenauth.Lang.Sthenauth (Sthenauth)
import Sthenauth.Types
import Sthenauth.Tables.Site as Site

--------------------------------------------------------------------------------
-- | Execute a 'Sthenauth' action, producing a Servant @Handler@.
runRequest
  :: forall a. Env
  -> Client
  -> Logger
  -> Sthenauth a
  -> Handler a
runRequest e client l s =
  liftIO (runScript (Runtime e (fst client)) enter) >>= \case
    Right (a, store') -> leave a store'
    Left  e' -> do
      liftIO (logger_error l (fst client) (show e' :: Text))
      throwError (toServerError e')

  where
    -- Prepare and then execute the request.
    enter :: Script a
    enter = withSite (Just (fst client ^. requestFqdn)) $ do
      sid <- whenNothingM (Site.pk <<$>> view envSite) (throwing _MissingSiteError ())
      whenJust (snd client) (currentUserFromSessionKey sid >=> assign storeUser)
      liftSthenauth s

    -- Actions to run after the request is done.
    leave :: a -> Store -> Handler a
    leave a _ = pure a
