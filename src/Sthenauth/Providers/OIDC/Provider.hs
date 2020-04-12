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
  , OidcClientId
  , OidcClientPassword(..)
  , newOidcProvider
  , registerOidcProvider
  , toOidcProvider
  , providerCredentials
  , fetchDiscoveryDocument
  , fetchProviderKeys
  , fromProviders
  , insertProviderReturningCount
  , refreshProviderCacheIfNeeded
  , providerById
  ) where

--------------------------------------------------------------------------------
import Control.Arrow (returnA)
import Control.Lens ((^.))
import Crypto.JOSE (JWKSet)
import Data.Binary (Binary)
import Data.Time.Clock (UTCTime)
import Iolaus.Database.JSON
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import qualified OpenID.Connect.Authentication as A
import OpenID.Connect.Client.Provider (Discovery, discovery, keysFromDiscovery)
import qualified OpenID.Connect.Client.Provider as P
import Sthenauth.Core.Crypto
import Sthenauth.Core.Database
import Sthenauth.Core.Error
import qualified Sthenauth.Core.HTTP as HTTP
import Sthenauth.Core.URL
import Sthenauth.Providers.OIDC.Known (KnownOidcProvider)
import qualified Sthenauth.Providers.OIDC.Known as Known

--------------------------------------------------------------------------------
-- | The primary key on the OpenID Connect providers table.
type ProviderId = Key UUID ProviderF

--------------------------------------------------------------------------------
type OidcClientId = A.ClientID

--------------------------------------------------------------------------------
data OidcClientPassword
  = OidcClientPlainPassword Text
  | OidcClientPasswordAssertion Text
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

  , providerLogoUrl :: Col f "logo_url" URL SqlText Required
    -- ^ A URL where a logo for the provider can be fetched from.

  , providerClientId :: Col f "client_id" Text SqlText Required
    -- ^ The client ID issued by the provider.

  , providerClientSecret :: Col f "client_secret" (Secret OidcClientPassword) SqlJsonb Required
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
newOidcProvider
  :: (Has Crypto sig m, Has (Throw Sterr) sig m)
  => HTTP.Client m
  -> KnownOidcProvider
  -> OidcClientId
  -> OidcClientPassword
  -> m (Insert [Provider])
newOidcProvider http kp cid pass = do
  safeClientSecret <- encrypt pass
  (disco, dcache)  <- fetchDiscoveryDocument http (kp ^. Known.discoveryUrl)
  (keys, kcache)   <- fetchProviderKeys http disco

  pure $
    toInsert $
      Provider
        { providerId                 = Nothing
        , providerEnabled            = toFields True
        , providerName               = toFields (kp ^. Known.providerName)
        , providerLogoUrl            = toFields (kp ^. Known.logoUrl)
        , providerClientId           = toFields cid
        , providerClientSecret       = toFields safeClientSecret
        , providerDiscoveryUrl       = toFields (kp ^. Known.discoveryUrl)
        , providerDiscoveryDoc       = toFields (LiftJSON disco)
        , providerDiscoveryExpiresAt = toFields dcache
        , providerJwkSet             = toFields (LiftJSON keys)
        , providerJwkSetExpiresAt    = toFields kcache
        , providerCreatedAt          = Nothing
        , providerUpdatedAt          = Nothing
        }

  where
    toInsert :: ProviderF SqlWrite -> Insert [Provider]
    toInsert p = Insert providers_openidconnect [p] (rReturning id) Nothing

--------------------------------------------------------------------------------
registerOidcProvider
  :: ( Has Crypto        sig m
     , Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => HTTP.Client m
  -> KnownOidcProvider
  -> OidcClientId
  -> OidcClientPassword
  -> m Provider
registerOidcProvider http kp oi op = do
  new <- newOidcProvider http kp oi op
  runQuery $ do
    Just p <- insert1 new
    pure p

--------------------------------------------------------------------------------
-- | Turn a provider record into one that can be used by the OpenID
-- Connect library.
toOidcProvider :: Provider -> P.Provider
toOidcProvider p =
  P.Provider
    { P.providerDiscovery = unliftJSON (providerDiscoveryDoc p)
    , P.providerKeys      = unliftJSON (providerJwkSet p)
    }

--------------------------------------------------------------------------------
-- | Create provider credentials from a provider record.
providerCredentials
  :: Has Crypto sig m
  => URL
  -> Provider
  -> m A.Credentials
providerCredentials url provider = do
  sec <- decrypt (providerClientSecret provider) <&> \case
    OidcClientPlainPassword t     -> A.AssignedSecretText t
    OidcClientPasswordAssertion t -> A.AssignedAssertionText t
  pure $
    A.Credentials
      { A.assignedClientId  = providerClientId provider
      , A.clientSecret      = sec
      , A.clientRedirectUri = getURI url
      }

--------------------------------------------------------------------------------
fetchDiscoveryDocument
  :: Has (Throw Sterr) sig m
  => HTTP.Client m
  -> URL
  -> m (Discovery, Maybe UTCTime)
fetchDiscoveryDocument http = discovery http . getURI >=>
  either (throwError . HttpException . SomeException) pure

--------------------------------------------------------------------------------
updateDiscoveryDocument
  :: Has (Throw Sterr) sig m
  => HTTP.Client m
  -> Provider
  -> m (ProviderF SqlRead -> ProviderF SqlRead)
updateDiscoveryDocument http p = do
  (doc, cache) <- fetchDiscoveryDocument http (providerDiscoveryUrl p)
  pure (\pr -> pr { providerDiscoveryDoc = toFields (LiftJSON doc)
                  , providerDiscoveryExpiresAt = toFields
                    (fromMaybe (providerDiscoveryExpiresAt p) cache)
                  })

--------------------------------------------------------------------------------
fetchProviderKeys
  :: Has (Throw Sterr) sig m
  => HTTP.Client m
  -> Discovery
  -> m (JWKSet, Maybe UTCTime)
fetchProviderKeys http = keysFromDiscovery http >=>
  either (throwError . HttpException . SomeException) pure

--------------------------------------------------------------------------------
updateProviderKeys
  :: Has (Throw Sterr) sig m
  => HTTP.Client m
  -> Provider
  -> m (ProviderF SqlRead -> ProviderF SqlRead)
updateProviderKeys http p = do
  (keys, cache) <- fetchProviderKeys http (unliftJSON (providerDiscoveryDoc p))
  pure (\pr -> pr { providerJwkSet = toFields (LiftJSON keys)
                  , providerJwkSetExpiresAt = toFields
                      (fromMaybe (providerJwkSetExpiresAt p) cache)
                  })

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

--------------------------------------------------------------------------------
-- | If a provider's cache needs to be updated, return the update
-- statement as a 'Left' value.  Otherwise return the given provider
-- in 'Right'.
refreshProviderCacheIfNeeded
  :: forall sig m. Has (Throw Sterr) sig m
  => HTTP.Client m              -- ^ The HTTP client function.
  -> UTCTime                    -- ^ The current time (for cache testing).
  -> Provider                   -- ^ The provider record to test.
  -> m (Either (Update [Provider]) Provider)
refreshProviderCacheIfNeeded http time provider
  | cacheValid provider = pure (Right provider)
  | otherwise = do
      f <- makeUpdateFunction provider
      pure . Left $
        Update
          { uTable      = providers_openidconnect
          , uUpdateWith = O.updateEasy (appEndo f)
          , uWhere      = \p -> providerId p .== toFields (providerId provider)
          , uReturning  = rReturning id
          }

  where
    cacheValid p     = discoveryValid p && keysValid p
    discoveryValid p = providerDiscoveryExpiresAt p > time
    keysValid p      = providerJwkSetExpiresAt p > time

    makeUpdateFunction :: Provider -> m (Endo (ProviderF SqlRead))
    makeUpdateFunction p = runM . execWriter $ do
      unless (discoveryValid p) $ do
        f <- sendM (updateDiscoveryDocument http p)
        tell (Endo f)
      unless (keysValid p) $ do
        f <- sendM (updateProviderKeys http p)
        tell (Endo f)
