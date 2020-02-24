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

An OpenID Connect session.

-}
module Sthenauth.Providers.OIDC.Session
  ( OidcSessionF(..)
  , OidcSession
  , OidcSessionId
  , BinaryClaimsSet(..)
  , ClaimsSet

  , PartialF(..)
  , Partial
  , PartialId

  , newPartialSession
  , fetchPartialSession
  , insertPartialReturningId
  , partialSessionQuery
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Crypto.JWT (ClaimsSet)
import Iolaus.Crypto.Salt
import Iolaus.Database.Extra
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Policy
import Sthenauth.Core.Remote
import Sthenauth.Core.Site (Site, SiteF(..), SiteId)
import Sthenauth.Crypto.Effect
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Providers.OIDC.Token

import Sthenauth.Core.Session
  ( SessionId
  , SessionKey
  , ClearSessionKey
  , newSessionKey
  , toSessionKey
  )

--------------------------------------------------------------------------------
-- | Primary key.
type OidcSessionId = Key UUID OidcSessionF

--------------------------------------------------------------------------------
data OidcSessionF f = OidcSession
  { oidcSessionId :: Col f "id" OidcSessionId SqlUuid ReadOnly
    -- ^ Primary key.

  , oidcSessionProviderId :: Col f "provider_id" ProviderId SqlUuid ForeignKey
    -- ^ Foreign key for the OpenID Connect provider.

  , foreignSessionId :: Col f "session_id" SessionId SqlUuid ForeignKey
    -- ^ Associated session.

  , oauthAccessToken :: Col f "access_token" (Secret Text) SqlJsonb Required
    -- ^ The access token that was issued.

  , oauthRefreshToken :: Col f "refresh_token" (Secret Text) SqlJsonb Nullable
    -- ^ Optional refresh token to get a new access token.

  , oauthTokenType :: Col f "token_type" Text SqlText Required
    -- ^ How to send the access token back to the provider.  Usually "Bearer".

  , identityToken :: Col f "id_token" (Secret BinaryClaimsSet) SqlJsonb Required

  , oauthAccessExpiresAt :: Col f "access_expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time the access token will expire and no longer be valid.

  , oidcExpiresAt :: Col f "id_expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time the id token will expire and no longer be valid.

  , oidcSessionCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.
  }


--------------------------------------------------------------------------------
-- | Monomorphic alias.
type OidcSession = OidcSessionF ForHask

--------------------------------------------------------------------------------
-- | Primary key.
type PartialId = Key UUID PartialF

--------------------------------------------------------------------------------
data PartialF f = Partial
  { partialId :: Col f "id" PartialId SqlUuid ReadOnly
    -- ^ Primary key.

  , partialProviderId :: Col f "provider_id" ProviderId SqlUuid ForeignKey
    -- ^ Foreign key for the OpenID Connect provider.

  , partialSiteId :: Col f "site_id" SiteId SqlUuid ForeignKey
    -- ^ The site this partial session was created for.

  , partialSessionKey :: Col f "session_key" SessionKey SqlBytea Required
    -- ^ Hashed key for looking up a session.

  , partialRemote :: Col f "remote" Remote SqlJsonb Required
    -- ^ Info about the remote connection that requested the session.

  , partialNonceBytes :: Col f "nonce_bytes" (Secret ByteString) SqlJsonb Required
    -- ^ Nonce for verifying an OpenID Connect callback.

  , partialExpiresAt :: Col f "expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time this state will expire and no longer be valid.

  , partialCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.
  }

makeTable ''PartialF "sessions_openidconnect_partial"

--------------------------------------------------------------------------------
-- | Monomorphic alias.
type Partial = PartialF ForHask

--------------------------------------------------------------------------------
-- | Create a new partial session that is ready to save to the database.
newPartialSession
  :: Has Crypto sig m
  => Remote
  -> Site
  -> ProviderId
  -> m (ClearSessionKey, PartialF SqlWrite)
newPartialSession rmt site pid = do
  key <- newSessionKey
  nonce <- encrypt =<< (encodeSalt <$> generateSaltSized 32)

  let expire = addSeconds (sitePolicy site ^. oidcPartialExpiresIn)
                          (rmt ^. requestTime)

  let partial = Partial
        { partialId         = Nothing
        , partialProviderId = O.toFields pid
        , partialSiteId     = O.toFields (siteId site)
        , partialSessionKey = O.toFields (key ^. _2)
        , partialRemote     = O.toFields rmt
        , partialNonceBytes = O.toFields nonce
        , partialExpiresAt  = O.toFields expire
        , partialCreatedAt  = Nothing
        }

  return (key ^. _1, partial)

--------------------------------------------------------------------------------
partialSessionQuery
  :: Has Crypto sig m
  => ClearSessionKey
  -> m (Select (PartialF SqlRead, ProviderF SqlRead))
partialSessionQuery clearKey = do
  key <- toSessionKey clearKey
  pure (fetchPartialSession key)

--------------------------------------------------------------------------------
-- | Fetch a 'Partial' and 'Provider' given a session key.
fetchPartialSession :: SessionKey -> Select (PartialF SqlRead, ProviderF SqlRead)
fetchPartialSession key = proc () -> do
  t1 <- selectTable sessions_openidconnect_partial -< ()
  t2 <- fromProviders -< ()
  O.restrict -< (partialExpiresAt  t1 .>  transactionTimestamp .&&
                 partialSessionKey t1 .== toFields key .&&
                 partialProviderId t1 .== providerId t2)
  returnA -< (t1, t2)

--------------------------------------------------------------------------------
insertPartialReturningId :: PartialF SqlWrite -> Query Partial
insertPartialReturningId p = do
  let table = sessions_openidconnect_partial
  Just p' <- insert1 (Insert table [p] (rReturning id) Nothing)
  pure p'
