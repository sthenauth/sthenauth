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
module Sthenauth.Providers.OIDC.Carrier
  ( OidcC
  , runOidc
  ) where

--------------------------------------------------------------------------------
import Control.Algebra
import Control.Carrier.Reader
import Control.Effect.Throw
import Control.Exception.Safe (try)
import qualified Data.ByteString as ByteString
import Network.HTTP.Client (Manager)
import Sthenauth.Core.Error
import Sthenauth.Core.Session (ClearSessionKey(..))
import Sthenauth.Core.Site (oidcCallbackURI)
import Sthenauth.Crypto.Effect
import Sthenauth.Providers.OIDC.Effect
import Sthenauth.Providers.OIDC.Partial
import Sthenauth.Providers.OIDC.Provider
import qualified Text.URI as URI
import qualified Web.OIDC.Client as WebOIDC
import Web.OIDC.Client.Discovery (discover)

--------------------------------------------------------------------------------
newtype OidcC m a = OidcC
  { runOidcC :: ReaderC Manager m a }
  deriving newtype (Functor, Applicative, Monad, MonadIO)

--------------------------------------------------------------------------------
instance (MonadIO m, Has Error sig m, Has Crypto sig m)
  => Algebra (OIDC :+: sig) (OidcC m) where
  alg = \case
    R other -> OidcC (alg (R (handleCoercible other)))

    ----------------------------------------------------------------------------
    L (ProviderDiscovery site provider k) -> do
      mgr <- OidcC ask
      liftIO (try $ discover (oidcUrl provider) mgr) >>= \case
        Left (_ :: SomeException) ->
          throwError (OidcDiscoveryError (providerName provider))
        Right x -> do
          let cb = URI.renderBs (oidcCallbackURI site)
              oidc = WebOIDC.newOIDC x
          cid <- decrypt (clientId provider)
          sec <- decrypt (clientSecret provider)
          k (Details (provider, WebOIDC.setCredentials cid sec cb oidc))

    ----------------------------------------------------------------------------
    L (GetRedirectUrl (ClearSessionKey key) partial (Details (provider, oidc)) k) -> do
      nonce <- decrypt (nonceBytes partial)
      let scope = [WebOIDC.openId, WebOIDC.email]
          keybs = Just (encodeUtf8 key)
          params = []
          session = WebOIDC.SessionStore
            { WebOIDC.sessionStoreGenerate = pure ByteString.empty
            , WebOIDC.sessionStoreSave = \_ _ -> pass
            , WebOIDC.sessionStoreGet = pure (keybs, Just nonce)
            , WebOIDC.sessionStoreDelete = pass
            }
          getUrl = WebOIDC.prepareAuthenticationRequestUrl session oidc scope params
      liftIO (try getUrl) >>= \case
        Left (_ :: SomeException) -> throwError (OidcRedirectError (providerName provider))
        Right uri -> k uri

    ----------------------------------------------------------------------------
    L (GetEmailToken partial details k) ->
      undefined


--------------------------------------------------------------------------------
runOidc :: Manager -> OidcC m a -> m a
runOidc mgr = runReader mgr . runOidcC
