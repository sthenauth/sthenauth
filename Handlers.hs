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
import Sthenauth.Core.PostLogin
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Core.Site (siteId, siteURL, pathToSiteUrl, oidcCookieName)
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
globalLogout = do
  site <- asks currentSite
  remote <- asks currentRemote
  cookie <- logout site remote
  pure (addHeader cookie ())

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
    Nothing -> redirectToSiteURL Nothing
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
    Nothing -> redirectToSiteURL Nothing
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
executeAuthN :: RequestAuthN -> Action Handler (SetCookie PostLogin)
executeAuthN req = do
  site <- asks currentSite
  remote <- asks currentRemote
  dischargeMonadRandom (requestAuthN site remote req) >>= \case
    LoggedIn cookie postLogin -> pure (addHeader cookie postLogin)
    LoggedOut cookie -> redirectToSiteURL cookie
    NextStep step -> lift (processNextStep step)

--------------------------------------------------------------------------------
processNextStep :: AdditionalStep -> Handler a
processNextStep = \case
  RedirectTo url cookie -> redirectToURL url (Just cookie)

--------------------------------------------------------------------------------
redirectToSiteURL :: Maybe WC.SetCookie -> Action Handler a
redirectToSiteURL cookie = do
  site <- asks currentSite
  lift (redirectToURL (siteURL site) cookie)

--------------------------------------------------------------------------------
redirectToURL :: URL -> Maybe WC.SetCookie -> Handler a
redirectToURL url cookie =
  CME.throwError $ err302
    { errHeaders = catMaybes
        [ Just ("Location", urlToByteString url)
        , ("Set-Cookie",) . hdrFromCookie <$> cookie
        ]
    }

--------------------------------------------------------------------------------
hdrFromCookie :: WC.SetCookie -> ByteString
hdrFromCookie = toStrict . toLazyByteString . WC.renderSetCookie
