{-# LANGUAGE Arrows #-}

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

Provider information for OpenID Connect authenticators.

-}
module Sthenauth.Providers.OIDC.Provider
  ( ProviderF(..)
  , Provider
  , ProviderId
  , ProviderPassword(..)
  , fetchDiscoveryDocument
  , fetchProviderKeys
  , fromProviders
  , insertProviderReturningCount
  , providerById
  ) where

--------------------------------------------------------------------------------
import Control.Arrow (returnA)
import Crypto.JOSE (JWKSet)
import Data.Binary (Binary)
import Iolaus.Database.JSON
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import OpenID.Connect.Client.Provider (Discovery, discovery, keysFromDiscovery)
import Sthenauth.Core.Error
import Sthenauth.Core.HTTP
import Sthenauth.Core.URL

--------------------------------------------------------------------------------
-- | The primary key on the OpenID Connect providers table.
type ProviderId = Key UUID ProviderF

--------------------------------------------------------------------------------
data ProviderPassword
  = ProviderPlainPassword Text
  | ProviderPasswordAssertion Text
  deriving stock Generic
  deriving anyclass Binary

--------------------------------------------------------------------------------
data ProviderF f = Provider
  { providerId :: Col f "id" ProviderId SqlUuid ReadOnly
    -- ^ Primary key.

  , providerEnabled :: Col f "enabled" Bool SqlBool Required
    -- ^ Whether or not this provider is available for use.

  , providerName :: Col f "provider_name" Text SqlText Required
    -- ^ The display name of the remote provider.

  , providerLogoUrl :: Col f "logo_url" URL SqlText Nullable
    -- ^ A URL where a logo for the provider can be fetched from.

  , providerClientId :: Col f "client_id" Text SqlText Required
    -- ^ The client ID issued by the provider.

  , providerClientSecret :: Col f "client_secret" (Secret ProviderPassword) SqlJsonb Required
    -- ^ Shared secret issued by the provider.

  , providerDiscoveryUrl :: Col f "discovery_url" URL SqlText Required
    -- ^ The provider's OIDC Discovery URL.

  , providerDiscoveryDoc :: Col f "discovery_doc" (LiftJSON Discovery) SqlJsonb Required
    -- ^ The provider's discovery document.

  , providerDiscoveryExpiresAt :: Col f "discovery_expires_at" UTCTime SqlTimestamptz Optional
    -- ^ The time the cached discovery document will expire.

  , providerJwkSet :: Col f "jwk_set" (LiftJSON JWKSet) SqlJsonb Required
    -- ^ The provider's signing/encrypting keys.

  , providerJwkSetExpiresAt :: Col f "jwk_set_expires_at" UTCTime SqlTimestamptz Optional
    -- ^ The time the cached JWK set will expire.

  , providerCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , providerUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was last updated.
  }

makeTable ''ProviderF "providers_openidconnect"

--------------------------------------------------------------------------------
-- | Monomorphic alias.
type Provider = ProviderF ForHask

--------------------------------------------------------------------------------
fetchDiscoveryDocument
  :: (Has HTTP sig m, Has Error sig m)
  => URL
  -> m (Discovery, Maybe UTCTime)
fetchDiscoveryDocument = discovery http . getURI >=>
  either (throwError . HttpException . SomeException) pure

--------------------------------------------------------------------------------
fetchProviderKeys
  :: (Has HTTP sig m, Has Error sig m)
  => Discovery
  -> m (JWKSet, Maybe UTCTime)
fetchProviderKeys = keysFromDiscovery http >=>
  either (throwError . HttpException . SomeException) pure

--------------------------------------------------------------------------------
-- | Restrict a query to only those providers that are active.
fromProviders :: Select (ProviderF SqlRead)
fromProviders = proc () -> do
  t <- selectTable providers_openidconnect -< ()
  O.restrict -< providerEnabled t
  returnA -< t

--------------------------------------------------------------------------------
providerById :: ProviderId -> Select (ProviderF SqlRead)
providerById pid = proc () -> do
  t <- fromProviders -< ()
  O.restrict -< (providerId t .== toFields pid)
  returnA -< t

--------------------------------------------------------------------------------
insertProviderReturningCount :: ProviderF SqlWrite -> Query Int64
insertProviderReturningCount p =
  insert (Insert providers_openidconnect [p] rCount Nothing)
