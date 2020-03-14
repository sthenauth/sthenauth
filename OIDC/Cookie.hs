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
module Sthenauth.Providers.OIDC.Cookie
  ( OidcCookie
  , newOidcCookie
  , lookupProviderFromOidcCookie
  , deleteOidcCookie
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Iolaus.Database.Extra
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Policy
import Sthenauth.Crypto.Effect
import Sthenauth.Providers.OIDC.Provider
import Web.Cookie

--------------------------------------------------------------------------------
data OidcCookieF f = OidcCookie
  { oidcHashedCookie :: Col f "hashed_cookie" (SaltedHash ByteString) SqlBytea Required

  , oidcCookieProviderId :: Col f "provider_id" ProviderId SqlUuid ForeignKey

  , oidcCookieExpiresAt :: Col f "expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time the cookie will expire and no longer be valid.

  , oidcCookieCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.
  }

makeTable ''OidcCookieF "openidconnect_cookies"

--------------------------------------------------------------------------------
type OidcCookie = OidcCookieF ForHask

--------------------------------------------------------------------------------
-- | Save a cookie in the database so a returning end-user can be verified.
newOidcCookie
  :: Has Crypto sig m
  => Policy     -- ^ Site policy.
  -> UTCTime    -- ^ Current time.
  -> SetCookie  -- ^ The cookie to save.
  -> ProviderId -- ^ The associated OIDC provider.
  -> m (Insert Int64)
newOidcCookie policy time cookie pid = do
    hashed <- toSaltedHash (setCookieValue cookie)
    pure . toInsert $
      OidcCookie
        { oidcHashedCookie     = toFields hashed
        , oidcCookieProviderId = toFields pid
        , oidcCookieExpiresAt  = toFields expiresT
        , oidcCookieCreatedAt  = Nothing
        }
  where
    toInsert :: OidcCookieF SqlWrite -> Insert Int64
    toInsert c = Insert openidconnect_cookies [c] rCount Nothing

    expiresT :: UTCTime
    expiresT = addSeconds (policy ^. oidcCookieExpiresIn) time

--------------------------------------------------------------------------------
-- | Find a provider record given a cookie's clear bytes.
--
-- The cookie record itself is also returned so you can delete it
-- after it's no longer needed.
lookupProviderFromOidcCookie
  :: Has Crypto sig m
  => ByteString -- ^ The raw cookie value from the browser.
  -> m (Select (OidcCookieF SqlRead, ProviderF SqlRead))
lookupProviderFromOidcCookie cookie = do
    hashed <- toSaltedHash cookie
    pure (query hashed)
  where
    query :: SaltedHash ByteString
          -> Select (OidcCookieF SqlRead, ProviderF SqlRead)
    query hashed = proc () -> do
      t0 <- selectTable openidconnect_cookies -< ()
      t1 <- fromProviders -< ()
      O.restrict -<
        (oidcCookieProviderId t0 .== providerId t1
          .&& oidcHashedCookie t0 .== toFields hashed
          .&& oidcCookieExpiresAt t0 .> transactionTimestamp)
      returnA -< (t0, t1)

--------------------------------------------------------------------------------
deleteOidcCookie
  :: OidcCookie
  -> Delete Int64
deleteOidcCookie cookie =
  Delete
    { dTable     = openidconnect_cookies
    , dWhere     = \c -> oidcHashedCookie c .== toFields (oidcHashedCookie cookie)
    , dReturning = rCount
    }
