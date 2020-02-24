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
module Sthenauth.Providers.Local.LocalAccount
  ( LocalAccount(..)
  , toLocalAccount
  , insertLocalAccountQuery
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Iolaus.Database.Query
import Iolaus.Database.Table (getKey)
import Opaleye (toFields, toNullable)
import qualified Opaleye as O
import Sthenauth.Core.Account as Account
import Sthenauth.Core.Email (toSafeEmail)
import Sthenauth.Core.Site as Site
import Sthenauth.Core.Username (getUsername)
import Sthenauth.Crypto.Effect
import Sthenauth.Providers.Local.Login (Login, getLogin)

--------------------------------------------------------------------------------
-- | A type representing an account local to this instance of
-- Sthenauth.  In other words, the account *must* contain a password
-- and is the sole identity for authentication.
data LocalAccount f = LocalAccount
  { accountM :: AccountF f
    -- ^ Account model record.

  , emailM :: AccountId -> [AccountEmailF f]
    -- ^ Function that can generate an email model given an account
    -- ID.  Only needed if an email address was provided.
  }

--------------------------------------------------------------------------------
-- | Given a 'Login' and hashed password, generate a new local account
-- record that is ready to insert into the database.
toLocalAccount
  :: forall sig m. Has Crypto sig m
  => SiteId
  -> Login
  -> Password Hashed
  -> m (LocalAccount SqlWrite)
toLocalAccount sid login passwd =
  LocalAccount mkAccount <$> mkEmail

  where
    -- Create an account record:
    mkAccount :: AccountF SqlWrite
    mkAccount = Account
      { accountId        = Nothing
      , accountCreatedAt = Nothing
      , accountUpdatedAt = Nothing
      , accountSiteId    = toFields sid
      , accountPassword  = toNullable (toFields passwd)
      , accountUsername  = either (toNullable . toFields . getUsername)
                            (const O.null) (getLogin login)
      }

    -- Create an email record:
    mkEmail :: m (AccountId -> [AccountEmailF SqlWrite])
    mkEmail =
      case getLogin login of
        Left _  -> pure (const []) -- Only username is available.
        Right e -> do      -- Email is available.
          et <- toSafeEmail e
          pure $ \key ->
            [ AccountEmail
                { emailId         = Nothing
                , emailCreatedAt  = Nothing
                , emailUpdatedAt  = Nothing
                , emailSiteId     = toFields sid
                , emailAccountId  = toFields (getKey key)
                , email           = toFields et
                , emailVerifiedAt = O.null
                }
            ]

--------------------------------------------------------------------------------
-- | A query that will insert a local account into the database,
-- returning the new account.
insertLocalAccountQuery
  :: LocalAccount SqlWrite
  -> Query Account
insertLocalAccountQuery LocalAccount{..} =
  createAccount accountM emailM
