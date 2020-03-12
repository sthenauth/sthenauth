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
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Crypto.JWT (ClaimsSet)
import Iolaus.Database.Table
import Sthenauth.Core.Session (SessionId)
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Providers.OIDC.Token

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
