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

An admin is an account with unrestricted access to Sthenauth.

-}
module Sthenauth.Core.Admin
  ( AdminF(..)
  , Admin
  , AlterAdmin(..)
  , fromAdmins
  , alterAdmin
  , insertAdmin
  , deleteAdmin
  , accountsAdminJoin
  , findAdmin
  , selectAdmin
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Data.Time.Clock (UTCTime(..))
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Account

--------------------------------------------------------------------------------
-- | The @admins@ table.
data AdminF f = Admin
  { adminAccountId :: Col f "account_id" AccountId SqlUuid ForeignKey
    -- ^ The account this email address is for (foreign key).

  , adminCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  } deriving Generic

makeTable ''AdminF "admins"

--------------------------------------------------------------------------------
-- | Monomorphic admin.
type Admin = AdminF ForHask

--------------------------------------------------------------------------------
fromAdmins :: Select (AdminF SqlRead)
fromAdmins = selectTable admins

--------------------------------------------------------------------------------
-- | Ways that an admin account can be altered.
data AlterAdmin
  = PromoteToAdmin -- ^ Insert a new row.
  | DemoteFromAdmin -- ^ Delete an existing row.

--------------------------------------------------------------------------------
-- | A query that will execute an 'AlterAdmin' command.
alterAdmin :: AccountId -> AlterAdmin -> Query ()
alterAdmin aid = \case
  PromoteToAdmin -> do
    n <- selectAdmin aid
    when (n == 0) $ void (insertAdmin aid)

  DemoteFromAdmin ->
    void (deleteAdmin aid)

--------------------------------------------------------------------------------
-- | Insert a new admin record for the given account.
insertAdmin :: AccountId -> Query (Maybe Admin)
insertAdmin aid = insert1 (ins $ Admin (toFields aid) Nothing)
  where
    ins :: AdminF SqlWrite -> O.Insert [Admin]
    ins a = Insert admins [a] (rReturning id) Nothing

--------------------------------------------------------------------------------
-- | Remove a admin record.
deleteAdmin :: AccountId -> Query Int64
deleteAdmin aid = delete $ O.Delete
  { O.dTable     = admins
  , O.dWhere     = \t -> adminAccountId t .== toFields aid
  , O.dReturning = O.rCount
  }

--------------------------------------------------------------------------------
-- | Join the accounts table to the admins table.
accountsAdminJoin :: SelectArr (AccountF SqlRead) (AdminF ForceNullable)
accountsAdminJoin = proc t1 ->
  O.leftJoinA (O.selectTable admins) -<
    (\t2 -> accountId t1 .== adminAccountId t2)

--------------------------------------------------------------------------------
-- | A query that will limit the admin records to those that are
-- associated with the given account.
findAdmin :: AccountId -> O.SelectArr (AdminF SqlRead) (AdminF SqlRead)
findAdmin aid = proc t -> do
  O.restrict -< adminAccountId t .== O.toFields aid
  returnA -< t

--------------------------------------------------------------------------------
-- | Count the number of admin records for the given account ID.
selectAdmin :: AccountId -> Query Int64
selectAdmin = count . query
  where
    query aid = proc () -> do
      t <- O.selectTable admins -< ()
      findAdmin aid -< t
      returnA -< t
