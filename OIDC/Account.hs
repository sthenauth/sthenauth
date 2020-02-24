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

Link accounts and providers.

-}
module Sthenauth.Providers.OIDC.Account
  ( OidcAccountF(..)
  , OidcAccount
  , ForeignAccountId
  , fromOidcAccounts
  , selectProviderAccount
  , insertOidcAccountReturningNothing
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Account
import Sthenauth.Providers.OIDC.Provider

--------------------------------------------------------------------------------
type ForeignAccountId = Text

--------------------------------------------------------------------------------
data OidcAccountF f = OidcAccount
  { oidcAccountId :: Col f "account_id" AccountId SqlUuid ForeignKey
    -- ^ Primary key.

  , accountProviderId :: Col f "provider_id" ProviderId SqlUuid ForeignKey
    -- ^ The provider who owns this account.

  , foreignAccountId :: Col f "foreign_id" Text SqlText Required
    -- ^ The internal ID used by the provider.

  , oidcAccountCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.
  }

makeTable ''OidcAccountF "accounts_openidconnect"

--------------------------------------------------------------------------------
type OidcAccount = OidcAccountF ForHask

--------------------------------------------------------------------------------
fromOidcAccounts :: Select (OidcAccountF SqlRead)
fromOidcAccounts = selectTable accounts_openidconnect

--------------------------------------------------------------------------------
selectProviderAccount
  :: ProviderId
  -> ForeignAccountId
  -> Select (OidcAccountF SqlRead)
selectProviderAccount pid aid = proc () -> do
  t <- fromOidcAccounts -< ()
  O.restrict -<
    (accountProviderId t .== toFields pid .&&
     foreignAccountId  t .== toFields aid)
  returnA -< t

--------------------------------------------------------------------------------
insertOidcAccountReturningNothing
  :: OidcAccountF SqlWrite
  -> Query ()
insertOidcAccountReturningNothing acct = do
  1 <- insert (Insert accounts_openidconnect [acct] rCount Nothing)
  pass
