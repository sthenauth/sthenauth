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
  , fromProviders
  , insertProviderReturningCount
  , providerById
  ) where

--------------------------------------------------------------------------------
import Control.Arrow (returnA)
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O

--------------------------------------------------------------------------------
-- | The primary key on the OpenID Connect providers table.
type ProviderId = Key UUID ProviderF

--------------------------------------------------------------------------------
data ProviderF f = Provider
  { providerId :: Col f "id" ProviderId SqlUuid ReadOnly
    -- ^ Primary key.

  , providerEnabled :: Col f "enabled" Bool SqlBool Required
    -- ^ Whether or not this provider is available for use.

  , providerName :: Col f "provider_name" Text SqlText Required
    -- ^ The display name of the remote provider.

  , providerLogoUrl :: Col f "logo_url" Text SqlText Nullable
    -- ^ A URL where a logo for the provider can be fetched from.

  , providerOidcUrl :: Col f "oidc_url" Text SqlText Required
    -- ^ The URL where OIDC connects begin (Issuer Location).

  , providerClientId :: Col f "client_id" (Secret ByteString) SqlJsonb Required
    -- ^ The client ID issued by the provider.

  , providerClientSecret :: Col f "client_secret" (Secret ByteString) SqlJsonb Required
    -- ^ Shared secret issued by the provider.

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
