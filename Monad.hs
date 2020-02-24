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
-- Imports:
import Control.Carrier.Database hiding (Runtime)
import Control.Carrier.Error.Either (runError)
import Control.Carrier.Lift
import Control.Monad.Except (throwError)
import Servant.Server
import Sthenauth.API.Log
import Sthenauth.API.Middleware (Client)
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Error hiding (throwError)
import Sthenauth.Core.Remote
import Sthenauth.Core.Runtime
import Sthenauth.Core.Site as Site
import Sthenauth.Crypto.Carrier hiding (Runtime)
import Sthenauth.Lang.Class
import Sthenauth.Lang.Script
import Sthenauth.Lang.Sthenauth (Sthenauth)

--------------------------------------------------------------------------------
-- | Execute a 'Sthenauth' action, producing a Servant @Handler@.
runRequest
  :: Runtime
  -> Client
  -> Logger
  -> Sthenauth a
  -> Handler a
runRequest env client l s = do
  site <- findSiteFromRequest
  cu <- findCurrentUser site

  liftIO (runScript env site (fst client) cu (liftSthenauth s)) >>= \case
    Right (_, a) -> pure a
    Left  e' -> do
      liftIO (logger_error l (fst client) (show e' :: Text))
      throwError (toServerError e')

  where
    findSiteFromRequest :: Handler Site
    findSiteFromRequest
      = siteFromFQDN (client ^. _1.requestFqdn)
      & runDatabase (rtDb env)
      & runError
      & runM
      & (>>= either (throwError . toServerError) pure)

    findCurrentUser :: Site -> Handler CurrentUser
    findCurrentUser site =
      case client ^. _2 of
        Nothing -> pure notLoggedIn
        Just session ->
          currentUserFromSessionKey site (client ^. _1.requestTime) session
          & runDatabase (rtDb env)
          & runCrypto (rtCrypto env)
          & runError
          & runM
          & (>>= either (\(_ :: BaseError) -> pure notLoggedIn) pure)
