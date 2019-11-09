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
-- Library Imports:
import Servant.API
import Servant.Server
import Web.Cookie (SetCookie)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Lang.Sthenauth (Sthenauth)
import Sthenauth.Scripts
import Sthenauth.Types
import Sthenauth.Tables.Session (resetSessionCookie, makeSessionCookie)

--------------------------------------------------------------------------------
-- | Type used when setting a cookie.
type SC a = Headers '[Header "Set-Cookie" SetCookie] a
type SCU = SC ()

--------------------------------------------------------------------------------
-- | Servant API type.
type API = "keys"   :> Get '[JSON] JWKSet
      :<|> "login"  :> ReqBody '[JSON] Credentials :> Post '[JSON] (SC PostLogin)
      :<|> "logout" :> Delete '[JSON] SCU

--------------------------------------------------------------------------------
-- | Handlers for the @API@ type, running in the 'Sthenauth' monad.
app :: ServerT API Sthenauth
app =  activeSiteKeys
  :<|> maybeAuthenticate
  :<|> logoutAndDeleteCookie

  where
    maybeAuthenticate :: Credentials -> Sthenauth (SC PostLogin)
    maybeAuthenticate c = do
      (session, postLogin) <- authenticate c
      return $ addHeader (makeSessionCookie "ss" session) postLogin

    logoutAndDeleteCookie :: Sthenauth SCU
    logoutAndDeleteCookie =
      logout >> return (addHeader (resetSessionCookie "ss") ())
