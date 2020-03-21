{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    git://code.devalot.com/sthenauth.git

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

-}
module Sthenauth.API.Routes
  ( Cookies(..)
  , SetCookie
  , GetKeys
  , GetSession
  , GetCapabilities
  , CreateLocalAccount
  , LocalLogin
  , GlobalLogout
  , OidcLogin
  , OidcReturnSucc
  , OidcReturnFail
  , OidcAPI
  , API
  , FinalAPI
  , api
  , finalapi
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Servant.API
import Sthenauth.Core.AuthN
import Sthenauth.Core.Capabilities
import Sthenauth.Core.JWK
import qualified Sthenauth.Core.Public as Public
import Sthenauth.Providers.Local.Login
import qualified Sthenauth.Providers.OIDC.AuthN as OIDC
import qualified Web.Cookie as WC

--------------------------------------------------------------------------------
newtype Cookies = Cookies ByteString
  deriving newtype (Eq, Ord)

--------------------------------------------------------------------------------
instance FromHttpApiData Cookies where
  parseUrlPiece = parseHeader . encodeUtf8
  parseHeader bs = Right (Cookies bs)

--------------------------------------------------------------------------------
-- | Type used when setting a cookie.
type SetCookie a = Headers '[Header "Set-Cookie" WC.SetCookie] a

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
  :> Post '[JSON] (SetCookie ResponseAuthN)

--------------------------------------------------------------------------------
type LocalLogin
  = "login"
  :> ReqBody '[JSON] Credentials
  :> Post '[JSON] (SetCookie ResponseAuthN)

--------------------------------------------------------------------------------
type GlobalLogout
  = "logout"
  :> Delete '[JSON] (SetCookie ResponseAuthN)

--------------------------------------------------------------------------------
type OidcLogin
  = "login"
  :> ReqBody '[JSON] OIDC.OidcLogin
  :> Post '[JSON] (SetCookie ResponseAuthN)

--------------------------------------------------------------------------------
type OidcReturnSucc
  = "done"
  :> QueryParam' '[Required, Strict] "code" Text
  :> QueryParam' '[Required, Strict] "state" Text
  :> Header' '[Required, Strict] "cookie" Cookies
  :> Get '[JSON] (SetCookie ResponseAuthN)

--------------------------------------------------------------------------------
type OidcReturnFail
  = "done"
  :> QueryParam' '[Required, Strict] "error" Text
  :> QueryParam "error_description" Text
  :> Header' '[Required, Strict] "cookie" Cookies
  :> Get '[JSON] (SetCookie ResponseAuthN)

--------------------------------------------------------------------------------
type OidcAPI
  = "oidc" :> (OidcLogin :<|> OidcReturnSucc :<|> OidcReturnFail)

--------------------------------------------------------------------------------
-- | Servant API type.
type API = GetKeys
      :<|> GetCapabilities
      :<|> GetSession
      :<|> LocalLogin
      :<|> GlobalLogout
      :<|> CreateLocalAccount
      :<|> OidcAPI

--------------------------------------------------------------------------------
-- | The proxy value for the 'Sthenauth' API.
api :: Proxy (TopPath :> API)
api = Proxy

--------------------------------------------------------------------------------
type TopPath = "auth"

--------------------------------------------------------------------------------
-- | The final API which includes a file server for the UI files.
type FinalAPI = TopPath :> Vault :> (API :<|> Raw)

--------------------------------------------------------------------------------
-- | The proxy value for the final API.
finalapi :: Proxy FinalAPI
finalapi = Proxy
