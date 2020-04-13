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

-}
module Sthenauth.Providers.Local.Provider
  ( Credentials(name)
  , authenticate
  , insertLocalAccountQuery
  , createNewLocalAccount
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Iolaus.Database.Query
import Iolaus.Database.Table (getKey)
import Sthenauth.Core.Account (Account, accountId, newAccount)
import Sthenauth.Core.Crypto
import Sthenauth.Core.Database
import Sthenauth.Core.Error
import Sthenauth.Core.Policy
import Sthenauth.Core.Remote
import Sthenauth.Providers.Local.Account
import Sthenauth.Providers.Local.Login
import Sthenauth.Providers.Local.Password
import Sthenauth.Providers.Types

--------------------------------------------------------------------------------
authenticate
  :: forall sig m.
     ( Has Crypto        sig m
     , Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => Policy
  -> RequestTime
  -> Credentials
  -> m ProviderResponse
authenticate policy rtime creds = do
    (login, passwd) <- whenNothing (fromCredentials creds) $
      throwUserError InvalidUsernameOrEmailError

    query <- accountByLogin login

    (sys, local) <- runQuery $ do
      Just a <- select1 query
      pure a

    verifyAndUpgradePassword policy rtime passwd local >>= \case
      PasswordIncorrect ->
        throwUserError (AuthenticationFailedError (Just . getKey . accountId $ sys))
      PasswordVerified ->
        pure (SuccessfulAuthN sys ExistingAccount)

--------------------------------------------------------------------------------
-- | Return a database query that will insert a new local account.
insertLocalAccountQuery
  :: ( Has Crypto        sig m
     , Has (Throw Sterr) sig m
     )
  => Policy
  -> RequestTime
  -> Credentials
  -> m (Query Account)
insertLocalAccountQuery policy rtime creds = do
  (login, clear) <- whenNothing (fromCredentials creds) $
    throwUserError InvalidUsernameOrEmailError

  strong <- asStrongPassword policy rtime clear
  hashed <- toHashedPassword strong
  actF <- newLocalAccount login hashed

  pure $ do
    Just a <- insert1 (newAccount (leftToMaybe $ getLogin login))
    mapM_ insert (actF $ accountId a)
    pure a

--------------------------------------------------------------------------------
-- | Create a new account and log in the new user.
createNewLocalAccount
  :: ( Has Crypto        sig m
     , Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => Policy
  -> RequestTime
  -> Credentials
  -> m ProviderResponse
createNewLocalAccount policy rtime creds = do
  query <- insertLocalAccountQuery policy rtime creds
  account <- transaction query
  pure (SuccessfulAuthN account NewAccount)
