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
import Data.List (lookup)
import qualified OpenID.Connect.Client.Flow.AuthorizationCode as OIDC
import Servant.API
import Servant.Links
import Servant.Server
import Sthenauth.API.Routes
import Sthenauth.Core.Action
import Sthenauth.Core.AuthN
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Info
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Core.Site (siteId, pathToSiteUrl, oidcCookieName)
import Sthenauth.Core.URL
import qualified Web.Cookie as WC

--------------------------------------------------------------------------------
-- | Handlers for the @API@ type.
app :: ServerT API (Action Handler)
app = getKeys
 :<|> getCapabilities
 :<|> getSession
 :<|> localLogin
 :<|> globalLogout
 :<|> createLocalAccount
 :<|> oidcDispatch

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
globalLogout = executeAuthN Logout

--------------------------------------------------------------------------------
createLocalAccount :: ServerT CreateLocalAccount (Action Handler)
createLocalAccount = executeAuthN . CreateLocalAccountWithCredentials

--------------------------------------------------------------------------------
oidcDispatch :: ServerT OidcAPI (Action Handler)
oidcDispatch = oidcLogin
          :<|> oidcReturnSucc
          :<|> oidcReturnFail

--------------------------------------------------------------------------------
oidcLogin :: ServerT OidcLogin (Action Handler)
oidcLogin login = do
  url <- oidcRedirectURL
  executeAuthN (LoginWithOidcProvider url login)

--------------------------------------------------------------------------------
oidcReturnSucc :: ServerT OidcReturnSucc (Action Handler)
oidcReturnSucc codeQp stateQp (Cookies cookies) = do
  site <- asks currentSite
  redir <- oidcRedirectURL

  case lookup (encodeUtf8 $ oidcCookieName site) (WC.parseCookies cookies) of
    Nothing -> pure (noHeader LoginFailed)
    Just bs ->
      executeAuthN $ FinishLoginWithOidcProvider redir $
        OIDC.UserReturnFromRedirect
          { afterRedirectCodeParam     = encodeUtf8 codeQp
          , afterRedirectStateParam    = encodeUtf8 stateQp
          , afterRedirectSessionCookie = bs
          }

--------------------------------------------------------------------------------
oidcReturnFail :: ServerT OidcReturnFail (Action Handler)
oidcReturnFail errQp errdQp (Cookies cookies) = do
  site <- asks currentSite

  case lookup (encodeUtf8 $ oidcCookieName site) (WC.parseCookies cookies) of
    Nothing -> pure (noHeader LoginFailed)
    Just bs ->
      executeAuthN . ProcessFailedOidcProviderLogin $
        IncomingOidcProviderError
          { oidcSessionCookieValue    = bs
          , oidcErrorParam            = errQp
          , oidcErrorDescriptionParam = errdQp
          }

--------------------------------------------------------------------------------
oidcRedirectURL :: Action Handler URL
oidcRedirectURL = do
  site <- asks currentSite
  let done = Proxy :: Proxy ("auth" :> "oidc" :> OidcReturnSucc)
      uri = linkURI (safeLink api done mempty mempty)
  pure (pathToSiteUrl ("/" <> uriPath uri) site)

--------------------------------------------------------------------------------
executeAuthN :: RequestAuthN -> Action Handler (SetCookie ResponseAuthN)
executeAuthN req = do
    site <- asks currentSite
    remote <- asks currentRemote
    (mc, res) <- dischargeMonadRandom (requestAuthN site remote req)
    pure (addCookieHeader mc res)
  where
    addCookieHeader :: Maybe WC.SetCookie -> a -> SetCookie a
    addCookieHeader Nothing = noHeader
    addCookieHeader (Just c) = addHeader c
