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
  , createNewLocalAccount
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((^.))
import Iolaus.Database.Table (getKey)
import Sthenauth.Core.Account (accountId)
import Sthenauth.Core.Crypto
import Sthenauth.Core.Database
import Sthenauth.Core.Error
import Sthenauth.Core.Remote
import Sthenauth.Core.Site (Site, siteId, sitePolicy)
import Sthenauth.Providers.Local.LocalAccount
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
  => Site
  -> Remote
  -> Credentials
  -> m ProviderResponse
authenticate site remote creds = do
    (login, passwd) <- whenNothing (fromCredentials creds) $
      throwUserError InvalidUsernameOrEmailError

    account <- getAccountFromLogin (siteId site) login >>=
      maybe (throwUserError (AuthenticationFailedError Nothing)) pure

    verifyAndUpgradePassword policy rtime passwd account >>= \case
      PasswordIncorrect ->
        throwUserError (AuthenticationFailedError (Just . getKey . accountId $ account))
      PasswordVerified ->
        pure (SuccessfulAuthN account ExistingAccount)

  where
    policy = sitePolicy site
    rtime = remote ^. requestTime

--------------------------------------------------------------------------------
-- | Create a new account and log in the new user.
createNewLocalAccount
  :: ( Has Crypto        sig m
     , Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => Site
  -> Remote
  -> Credentials
  -> m ProviderResponse
createNewLocalAccount site remote creds = do
  let policy = sitePolicy site
      rtime  = remote ^. requestTime

  (login, clear) <- whenNothing (fromCredentials creds) $
    throwUserError InvalidUsernameOrEmailError

  strong <- asStrongPassword policy rtime clear
  hashed <- toHashedPassword strong
  la <- toLocalAccount (siteId site) login hashed

  SuccessfulAuthN
    <$> insertLocalAccount la
    <*> pure NewAccount
