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
import Servant.Server
import Sthenauth.API.Routes
import Sthenauth.Core.Action
import Sthenauth.Core.AuthN
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Info
import Sthenauth.Core.PostLogin
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Core.Site (siteId, oidcCookieName)
import Sthenauth.Core.URL
import qualified Web.Cookie as WC

--------------------------------------------------------------------------------
data UI
  = BareBrowser -- ^ Don't send JSON to this thing
  | JsonApp     -- ^ JSON okay!

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
  site   <- asks currentSite
  remote <- asks currentRemote
  cfg    <- asks currentConfig
  getSiteCapabilities cfg site remote

--------------------------------------------------------------------------------
getSession :: ServerT GetSession (Action Handler)
getSession = fmap sessionFromCurrentUser get >>= \case
  Nothing -> lift (CME.throwError err401)
  Just s  -> pure (Public.toSession s)

--------------------------------------------------------------------------------
localLogin :: ServerT LocalLogin (Action Handler)
localLogin = executeAuthN JsonApp . LoginWithLocalCredentials

--------------------------------------------------------------------------------
globalLogout :: ServerT GlobalLogout (Action Handler)
globalLogout = executeAuthN JsonApp Logout

--------------------------------------------------------------------------------
createLocalAccount :: ServerT CreateLocalAccount (Action Handler)
createLocalAccount = executeAuthN JsonApp . CreateLocalAccountWithCredentials

--------------------------------------------------------------------------------
oidcDispatch :: ServerT OidcAPI (Action Handler)
oidcDispatch = oidcLogin
          :<|> oidcReturnSucc
          :<|> oidcReturnFail

--------------------------------------------------------------------------------
oidcLogin :: ServerT OidcLogin (Action Handler)
oidcLogin login = do
  url <- asks currentSite <&> oidcRedirectURL
  executeAuthN JsonApp (LoginWithOidcProvider url login)

--------------------------------------------------------------------------------
oidcReturnSucc :: ServerT OidcReturnSucc (Action Handler)
oidcReturnSucc codeQp stateQp (Cookies cookies) = do
  site <- asks currentSite
  let redir = oidcRedirectURL site

  case lookup (encodeUtf8 $ oidcCookieName site) (WC.parseCookies cookies) of
    Nothing -> pure (noHeader LoginFailed)
    Just bs ->
      executeAuthN BareBrowser $ FinishLoginWithOidcProvider redir $
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
      executeAuthN BareBrowser . ProcessFailedOidcProviderLogin $
        IncomingOidcProviderError
          { oidcSessionCookieValue    = bs
          , oidcErrorParam            = errQp
          , oidcErrorDescriptionParam = errdQp
          }

--------------------------------------------------------------------------------
executeAuthN :: UI -> RequestAuthN -> Action Handler (SetCookie ResponseAuthN)
executeAuthN ui req = do
    site <- asks currentSite
    remote <- asks currentRemote
    (mc, res) <- dischargeMonadRandom (requestAuthN site remote req)

    case ui of
      BareBrowser -> lift (simpleResponse mc res)
      JsonApp     -> pure (addCookieHeader mc res)
  where
    addCookieHeader :: Maybe WC.SetCookie -> a -> SetCookie a
    addCookieHeader Nothing = noHeader
    addCookieHeader (Just c) = addHeader c

--------------------------------------------------------------------------------
simpleResponse :: Maybe WC.SetCookie -> ResponseAuthN -> Handler a
simpleResponse cookie res =
    CME.throwError $ err302
      { errHeaders =
          ("Location", url res)
          : maybe [] (pure . ("Set-Cookie",) . renderCookie) cookie
      }
  where
    renderCookie :: WC.SetCookie -> ByteString
    renderCookie = toStrict . toLazyByteString . WC.renderSetCookie

    url :: ResponseAuthN -> ByteString
    url = \case
      LoginFailed -> "/" -- FIXME: find a better URL to send the user to.
      LoggedIn PostLogin{postLoginUrl} -> urlToByteString postLoginUrl
      NextStep (RedirectTo url) -> urlToByteString url
      LoggedOut -> "/"
