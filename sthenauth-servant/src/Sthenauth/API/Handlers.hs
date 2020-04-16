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
import qualified OpenID.Connect.Client.Flow.AuthorizationCode as OIDC
import Servant.API
import Servant.Server
import Sthenauth.API.Monad (Action)
import Sthenauth.API.Routes
import Sthenauth.Core.AuthN
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Error
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Core.URL
import Sthenauth.Effect hiding (SetCookie, OidcLogin)
import qualified Web.Cookie as WC

--------------------------------------------------------------------------------
data UI
  = BareBrowser -- ^ Don't send JSON to this thing
  | JsonApp     -- ^ JSON okay!

--------------------------------------------------------------------------------
-- | Handlers for the @API@ type.
app :: ServerT API Action
app = getCapabilitiesH
 :<|> getSessionH
 :<|> localLoginH
 :<|> logoutH
 :<|> createLocalAccountH
 :<|> oidcDispatchH

--------------------------------------------------------------------------------
getCapabilitiesH :: ServerT GetCapabilities Action
getCapabilitiesH = getCapabilities

--------------------------------------------------------------------------------
getSessionH :: ServerT GetSession Action
getSessionH =
  getCurrentUser
    <&> sessionFromCurrentUser
    >>= maybe (throwUserError PermissionDenied)
              (pure . Public.toSession)

--------------------------------------------------------------------------------
localLoginH :: ServerT LocalLogin Action
localLoginH = loginWithCredentials >=> responseAuthN JsonApp

--------------------------------------------------------------------------------
logoutH :: ServerT GlobalLogout Action
logoutH = logout <&> (`addHeader` LoggedOut)

--------------------------------------------------------------------------------
createLocalAccountH :: ServerT CreateLocalAccount Action
createLocalAccountH = createAccount >=> responseAuthN JsonApp

--------------------------------------------------------------------------------
oidcDispatchH :: ServerT OidcAPI Action
oidcDispatchH = oidcLoginH :<|> oidcReturnSuccH :<|> oidcReturnFailH

--------------------------------------------------------------------------------
oidcLoginH :: ServerT OidcLogin Action
oidcLoginH login = do
  url <- getCurrentRemote <&> oidcRedirectURL
  loginWithOidcProvider url login >>= responseAuthN JsonApp

--------------------------------------------------------------------------------
oidcReturnSuccH :: ServerT OidcReturnSucc Action
oidcReturnSuccH codeQp stateQp (Cookies cookies) = do
  let user = OIDC.UserReturnFromRedirect
        { afterRedirectCodeParam     = encodeUtf8 codeQp
        , afterRedirectStateParam    = encodeUtf8 stateQp
        , afterRedirectSessionCookie = cookies
        }
  url <- getCurrentRemote <&> oidcRedirectURL
  finishLoginWithOidcProvider url user >>= responseAuthN BareBrowser

--------------------------------------------------------------------------------
oidcReturnFailH :: ServerT OidcReturnFail Action
oidcReturnFailH errQp errdQp (Cookies cookies) = do
  let oidc = IncomingOidcProviderError
        { oidcSessionCookieValue    = cookies
        , oidcErrorParam            = errQp
        , oidcErrorDescriptionParam = errdQp
        }
  processFailedOidcProviderLogin oidc >>= responseAuthN BareBrowser

--------------------------------------------------------------------------------
responseAuthN
  :: UI
  -> (Maybe WC.SetCookie, ResponseAuthN)
  -> Action (SetCookie ResponseAuthN)
responseAuthN ui (mc, res) =
  case ui of
    BareBrowser -> sendM (simpleResponse  mc res)
    JsonApp     -> pure  (addCookieHeader mc res)
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
      LoggedIn -> "/"
      NextStep (RedirectTo url) -> urlToByteString url
      LoggedOut -> "/"
