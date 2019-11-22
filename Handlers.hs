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
import qualified Data.Aeson as Aeson
import Servant.API
import Servant.Server
import Web.Cookie (SetCookie)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Lang.Sthenauth
import Sthenauth.Scripts
import Sthenauth.Types
import Sthenauth.Tables.Session (resetSessionCookie, makeSessionCookie)

--------------------------------------------------------------------------------
-- | Respond to a @ping@.
-- FIXME: Replace with an endpoint for fetching session details such
-- as the time the session will become inactive.
data Pong = Pong

instance ToJSON Pong where
  toJSON _ = Aeson.object [ "response" Aeson..= ("pong" :: Text) ]

--------------------------------------------------------------------------------
-- | Type used when setting a cookie.
type SC a = Headers '[Header "Set-Cookie" SetCookie] a
type SCU = SC ()

--------------------------------------------------------------------------------
-- | Servant API type.
type API = "keys" :> Get '[JSON] JWKSet
      :<|> "capabilities" :> Get '[JSON] Capabilities
      :<|> "create" :> ReqBody '[JSON] Credentials :> Post '[JSON] (SC PostLogin)
      :<|> "login" :> ReqBody '[JSON] Credentials :> Post '[JSON] (SC PostLogin)
      :<|> "logout" :> Delete '[JSON] SCU
      :<|> "ping" :> Get '[JSON] Pong

--------------------------------------------------------------------------------
-- | Handlers for the @API@ type, running in the 'Sthenauth' monad.
app :: ServerT API Sthenauth
app =  activeSiteKeys
  :<|> getCapabilities
  :<|> maybeCreateNewLocalAccount
  :<|> maybeAuthenticate
  :<|> logoutAndDeleteCookie
  :<|> handlePing

  where
    maybeAuthenticate :: Credentials -> Sthenauth (SC PostLogin)
    maybeAuthenticate c = do
      (session, clear, postLogin) <- authenticate c
      return $ addHeader (makeSessionCookie "ss" clear session) postLogin

    logoutAndDeleteCookie :: Sthenauth SCU
    logoutAndDeleteCookie =
      logout >> return (addHeader (resetSessionCookie "ss") ())

    maybeCreateNewLocalAccount :: Credentials -> Sthenauth (SC PostLogin)
    maybeCreateNewLocalAccount c = do
      (session, clear, postLogin) <- createNewLocalAccount c
      return $ addHeader (makeSessionCookie "ss" clear session) postLogin

    handlePing :: Sthenauth Pong
    handlePing = withValidUser $ \_ -> return Pong
