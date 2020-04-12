{-# LANGUAGE Arrows #-}

{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    https://code.devalot.com/sthenauth/sthenauth

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

-}
module Sthenauth.Providers.Local.Account
  ( LocalAccountF(..)
  , LocalAccount
  , newLocalAccount
  , accountByLogin
  , changePassword
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Data.Time.Clock (UTCTime)
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Account as Account
import Sthenauth.Core.Crypto
import Sthenauth.Core.Email (SafeEmail, toSafeEmail, getEmail)
import Sthenauth.Providers.Local.Login (Login, getLogin)

--------------------------------------------------------------------------------
data LocalAccountF f = LocalAccount
  { localAccountId :: Col f "account_id" AccountId SqlUuid ForeignKey
  , localAccountPassword :: Col f "password" (Password Hashed) SqlJsonb Required
  , localAccountCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
  , localAccountUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
  }

makeTable ''LocalAccountF "accounts_local"

type LocalAccount = LocalAccountF ForHask

--------------------------------------------------------------------------------
newLocalAccount
  :: Has Crypto sig m
  => Login
  -> Password Hashed
  -> m (AccountId -> NonEmpty (Insert Int64))
newLocalAccount login password =
  case getLogin login of
    Left _ ->
      pure $ go Nothing

    Right email -> do
      safe <- toSafeEmail email
      pure $ go (Just safe)

  where
    go :: Maybe SafeEmail -> AccountId -> NonEmpty (Insert Int64)
    go email aid = newLA aid
                :| maybe [] (\e -> [newAccountEmail e Nothing aid]) email

    newLA :: AccountId -> Insert Int64
    newLA aid = toInsert $
      LocalAccount
        { localAccountId        = toFields aid
        , localAccountPassword  = toFields password
        , localAccountCreatedAt = Nothing
        , localAccountUpdatedAt = Nothing
        }

    toInsert :: LocalAccountF SqlWrite -> Insert Int64
    toInsert la = Insert accounts_local [la] rCount Nothing

--------------------------------------------------------------------------------
-- | Find an account using a username or an email address.
accountByLogin
  :: Has Crypto sig m
  => Login
  -> m (Select (AccountF SqlRead, LocalAccountF SqlRead))
accountByLogin l =
  case getLogin l of
    Left  u -> pure $ query (findAccountByUsername u)
    Right e -> query . findAccountByEmail <$> toSaltedHash (getEmail e)

  where
    -- Restrict the accounts table then run a sub-query.
    query
      :: O.SelectArr (AccountF SqlRead) (AccountF SqlRead)
      -> O.Select (AccountF SqlRead, LocalAccountF SqlRead)
    query sub = proc () -> do
      t1 <- fromAccounts -< ()
      t2 <- sub -< t1
      t3 <- selectTable accounts_local -< ()
      O.restrict -< localAccountId t3 .== accountId t2
      returnA -< (t2, t3)

--------------------------------------------------------------------------------
changePassword :: AccountId -> Password Hashed -> Update Int64
changePassword aid passwd =
  Update
    { uTable = accounts_local
    , uUpdateWith = O.updateEasy (\a -> a {localAccountPassword = toFields passwd})
    , uWhere = \a -> localAccountId a .== toFields aid
    , uReturning = rCount
    }
