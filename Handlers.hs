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
module Sthenauth.API.Handlers
  ( API
  , app
  ) where


--------------------------------------------------------------------------------
-- Imports:
import qualified Control.Monad.Except as CME
import Data.ByteString.Builder (toLazyByteString)
import Servant.API
import Servant.Server
import Sthenauth.Core.Action
import Sthenauth.Core.AuthN
import Sthenauth.Core.Capabilities
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Info
import Sthenauth.Core.JWK
import Sthenauth.Core.PostLogin
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Core.Site (siteId)
import Sthenauth.Core.URL
import Sthenauth.Providers.Local.Login
import Web.Cookie

--------------------------------------------------------------------------------
-- | Type used when setting a cookie.
type Cookie a = Headers '[Header "Set-Cookie" SetCookie] a

--------------------------------------------------------------------------------
type GetKeys
  = "keys"
  :> Get '[JSON] JWKSet

--------------------------------------------------------------------------------
type GetCapabilities
  = "capabilities"
  :> Get '[JSON] Capabilities

--------------------------------------------------------------------------------
type GetSession
  = "session"
  :> Get '[JSON] Public.Session

--------------------------------------------------------------------------------
type CreateLocalAccount
  = "create"
  :> ReqBody '[JSON] Credentials
  :> Post '[JSON] (Cookie PostLogin)

--------------------------------------------------------------------------------
type LocalLogin
  = "login"
  :> ReqBody '[JSON] Credentials
  :> Post '[JSON] (Cookie PostLogin)

--------------------------------------------------------------------------------
type GlobalLogout
  = "logout"
  :> Delete '[JSON] (Cookie ())

--------------------------------------------------------------------------------
-- | Servant API type.
type API = GetKeys
      :<|> GetCapabilities
      :<|> GetSession
      :<|> LocalLogin
      :<|> GlobalLogout
      :<|> CreateLocalAccount

--------------------------------------------------------------------------------
-- | Handlers for the @API@ type.
app :: ServerT API (Action Handler)
app = getKeys
 :<|> getCapabilities
 :<|> getSession
 :<|> localLogin
 :<|> globalLogout
 :<|> createLocalAccount

--------------------------------------------------------------------------------
getKeys :: ServerT GetKeys (Action Handler)
getKeys = do
  site <- asks currentSite
  getSitePublicKeys (siteId site)

--------------------------------------------------------------------------------
getCapabilities :: ServerT GetCapabilities (Action Handler)
getCapabilities = do
  site <- asks currentSite
  cfg  <- asks currentConfig
  getSiteCapabilities cfg site

--------------------------------------------------------------------------------
getSession :: ServerT GetSession (Action Handler)
getSession = fmap sessionFromCurrentUser get >>= \case
  Nothing -> lift (CME.throwError err401)
  Just s  -> pure (Public.toSession s)

--------------------------------------------------------------------------------
localLogin :: ServerT LocalLogin (Action Handler)
localLogin = executeAuthN . LoginWithLocalCredentials

--------------------------------------------------------------------------------
globalLogout :: ServerT GlobalLogout (Action Handler)
globalLogout = do
  site <- asks currentSite
  remote <- asks currentRemote
  cookie <- logout site remote
  pure (addHeader cookie ())

--------------------------------------------------------------------------------
createLocalAccount :: ServerT CreateLocalAccount (Action Handler)
createLocalAccount = executeAuthN . CreateLocalAccountWithCredentials

--------------------------------------------------------------------------------
executeAuthN :: RequestAuthN -> Action Handler (Cookie PostLogin)
executeAuthN req = do
  site <- asks currentSite
  remote <- asks currentRemote
  requestAuthN site remote req >>= \case
    LoggedIn cookie postLogin -> pure (addHeader cookie postLogin)
    LoggedOut -> lift (CME.throwError err401)
    NextStep step -> lift (processNextStep step)

--------------------------------------------------------------------------------
processNextStep :: AdditionalStep -> Handler a
processNextStep = \case
  RedirectTo url cookie ->
    CME.throwError $ err302
      { errHeaders =
          [ ("Location",   urlToByteString url)
          , ("Set-Cookie", toStrict (toLazyByteString (renderSetCookie cookie)))
          ]
      }
