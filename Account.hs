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

An account is the primary way someone authenticates with Sthenauth.

-}
module Sthenauth.Core.Account
  ( AccountF(..)
  , Account
  , AccountId
  , AccountEmailF(..)
  , AccountEmail
  , AccountEmailId
  , fromAccounts
  , createAccount
  , findAccountByUsername
  , emailHashed
  , findAccountByEmail
  , changePassword
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Email (SafeEmail)
import Sthenauth.Core.Site (SiteId)
import Sthenauth.Core.Username

--------------------------------------------------------------------------------
-- | The primary key on the @accounts@ table.
type AccountId = Key UUID AccountF

--------------------------------------------------------------------------------
-- | The accounts table in the database.
data AccountF f = Account
  { accountId :: Col f "id" AccountId SqlUuid ReadOnly
    -- ^ Primary key.

  , accountSiteId :: Col f "site_id" SiteId SqlUuid ForeignKey
    -- ^ The site this account belongs to.

  , accountUsername :: Col f "username" Username SqlText Nullable
    -- ^ Optional username.  Sthenauth can be configured to allow users
    -- to set a username, or they may simply authenticate with an email
    -- address, or both.

  , accountPassword :: Col f "password" (Password Hashed) SqlJsonb Nullable
    -- ^ Optional password.  Users may be authenticating via OAuth in
    -- which case they will not have a local password.

  , accountCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , accountUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was last updated.

  } deriving Generic

makeTable ''AccountF "accounts"

--------------------------------------------------------------------------------
-- | Monomorphic account.
type Account = AccountF ForHask

--------------------------------------------------------------------------------
-- | Primary key for the @emails@ table.
type AccountEmailId = Key UUID AccountEmailF

--------------------------------------------------------------------------------
-- | The @emails@ table.
data AccountEmailF f = AccountEmail
  { emailId :: Col f "id" AccountEmailId SqlUuid ReadOnly
    -- ^ Primary key.

  , emailSiteId :: Col f "site_id" SiteId SqlUuid ForeignKey
  -- ^ The site this email address is for (foreign key).

  , emailAccountId :: Col f "account_id" AccountId SqlUuid ForeignKey
  -- ^ The account this email address is for (foreign key).

  , email :: Col f "email" SafeEmail SqlJsonb Required
  -- ^ Encrypted version of the email address so it can be fetched and
  -- used by the primary application but is still safe at rest.

  , emailVerifiedAt :: Col f "verified_at" UTCTime SqlTimestamptz Nullable
    -- ^ If set, the time this email address was verified by a link
    -- sent in an email.

  , emailCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
  -- ^ The time this record was created.

  , emailUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
  -- ^ The time this record was last updated.

  } deriving Generic

deriving via (GenericJSON (AccountEmailF ForUI)) instance ToJSON   (AccountEmailF ForUI)
deriving via (GenericJSON (AccountEmailF ForUI)) instance FromJSON (AccountEmailF ForUI)
makeTable ''AccountEmailF "emails"

--------------------------------------------------------------------------------
--  | Monomorphic email.
type AccountEmail = AccountEmailF ForHask

--------------------------------------------------------------------------------
-- | Properly select from the accounts table.
--
-- FIXME: Add a column to lock an account and check it here.
fromAccounts :: Select (AccountF SqlRead)
fromAccounts = selectTable accounts

--------------------------------------------------------------------------------
-- | FIXME: This should use ForUI and do validation.
createAccount
  :: AccountF SqlWrite
  -> (AccountId -> [AccountEmailF SqlWrite])
  -> Query Account
createAccount acct emailf = do
    Just a <- insert1 (insA acct)
    _ <- insert (insEs (emailf (accountId a)))
    pure a
  where
    insA :: AccountF SqlWrite -> O.Insert [Account]
    insA a = Insert accounts [a] (O.rReturning id) Nothing

    insEs :: [AccountEmailF SqlWrite] -> O.Insert Int64
    insEs es = Insert emails es O.rCount Nothing

--------------------------------------------------------------------------------
-- | Access just the hashed portion of an email address.
emailHashed :: AccountEmailF SqlRead -> O.FieldNullable SqlJsonb
emailHashed e = O.toNullable (email e) .-> sqlStrictText "hashed"

--------------------------------------------------------------------------------
-- | Find an account based on an email address.
findAccountByEmail
  :: SaltedHash Text
  -> O.SelectArr (AccountF SqlRead) (AccountF SqlRead)
findAccountByEmail ehash = proc t1 -> do
  t2 <- O.selectTable emails -< ()

  O.restrict -<
    emailAccountId t2 .== accountId t1     .&&
    emailSiteId t2    .== accountSiteId t1 .&&
    emailHashed t2    .== O.toNullable (sqlValueJSONB ehash)

  returnA -< t1

--------------------------------------------------------------------------------
-- Find an account with a username.
findAccountByUsername :: Username -> SelectArr (AccountF SqlRead) (AccountF SqlRead)
findAccountByUsername un = proc t1 -> do
  let cmp field = O.lower field .== O.toFields un
  O.restrict -< O.matchNullable (O.sqlBool False) cmp (accountUsername t1)
  returnA -< t1

--------------------------------------------------------------------------------
changePassword :: AccountId -> Password Hashed -> Update Int64
changePassword aid passwd =
  let nulled = O.toNullable (O.toFields passwd)
  in Update
    { uTable = accounts
    , uUpdateWith = O.updateEasy (\a -> a {accountPassword = nulled})
    , uWhere = \a -> accountId a .== toFields aid
    , uReturning = rCount
    }
