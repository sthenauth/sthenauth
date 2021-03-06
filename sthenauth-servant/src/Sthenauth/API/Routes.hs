-- |
--
-- Copyright:
--   This file is part of the package sthenauth. It is subject to the
--   license terms in the LICENSE file found in the top-level directory
--   of this distribution and at:
--
--     git://code.devalot.com/sthenauth.git
--
--   No part of this package, including this file, may be copied,
--   modified, propagated, or distributed except according to the terms
--   contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.API.Routes
  ( Cookies (..),
    SetCookie,
    GetSession,
    GetCapabilities,
    CreateLocalAccount,
    LocalLogin,
    GlobalLogout,
    OidcLogin,
    OidcReturnSucc,
    OidcReturnFail,
    OidcAPI,
    API,
    TopPath,
    api,
    oidcRedirectURL,
  )
where

-- Imports:
import Control.Lens ((%~), (.~), (^.))
import Servant.API
import Servant.Links
import Sthenauth.Core.AuthN
import Sthenauth.Core.Capabilities
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Core.Remote (Remote, requestFqdn)
import Sthenauth.Core.URL
import Sthenauth.Providers.Local.Login
import qualified Sthenauth.Providers.OIDC.AuthN as OIDC
import qualified Web.Cookie as WC

newtype Cookies = Cookies ByteString
  deriving newtype (Eq, Ord)

instance FromHttpApiData Cookies where
  parseUrlPiece = parseHeader . encodeUtf8
  parseHeader bs = Right (Cookies bs)

-- | All routes fall under this top-level path component.
type TopPath = "auth"

-- | Type used when setting a cookie.
type SetCookie a = Headers '[Header "Set-Cookie" WC.SetCookie] a

type GetCapabilities =
  "capabilities"
    :> Get '[JSON] Capabilities

type GetSession =
  "session"
    :> Get '[JSON] Public.Session

type CreateLocalAccount =
  "create"
    :> ReqBody '[JSON] Credentials
    :> Post '[JSON] (SetCookie ResponseAuthN)

type LocalLogin =
  "login"
    :> ReqBody '[JSON] Credentials
    :> Post '[JSON] (SetCookie ResponseAuthN)

type GlobalLogout =
  "logout"
    :> Delete '[JSON] (SetCookie ResponseAuthN)

type OidcLogin =
  "login"
    :> ReqBody '[JSON] OIDC.OidcLogin
    :> Post '[JSON] (SetCookie ResponseAuthN)

type OidcReturnSucc =
  "done"
    :> QueryParam' '[Required, Strict] "code" Text
    :> QueryParam' '[Required, Strict] "state" Text
    :> Header' '[Required, Strict] "cookie" Cookies
    :> Get '[JSON] (SetCookie ResponseAuthN)

type OidcReturnFail =
  "done"
    :> QueryParam' '[Required, Strict] "error" Text
    :> QueryParam "error_description" Text
    :> Header' '[Required, Strict] "cookie" Cookies
    :> Get '[JSON] (SetCookie ResponseAuthN)

type OidcAPI =
  "oidc" :> (OidcLogin :<|> OidcReturnSucc :<|> OidcReturnFail)

-- | Servant API type.
type API =
  GetCapabilities
    :<|> GetSession
    :<|> LocalLogin
    :<|> GlobalLogout
    :<|> CreateLocalAccount
    :<|> OidcAPI

-- | The proxy value for the 'Sthenauth' API.
api :: Proxy (TopPath :> API)
api = Proxy

oidcRedirectURL :: Remote -> URL
oidcRedirectURL remote =
  let done = Proxy :: Proxy (TopPath :> "oidc" :> OidcReturnSucc)
      uri = linkURI (safeLink api done mempty mempty)
   in uri & urlDomain .~ (remote ^. requestFqdn)
        & urlScheme .~ "https:"
        & urlPath %~ ("/" <>)
        & urlFromURI
