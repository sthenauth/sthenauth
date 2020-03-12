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
module Sthenauth.Providers.Local.Password
  ( PasswordStatus(..)
  , asStrongPassword
  , verifyAndUpgradePassword
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Iolaus.Crypto.Password as Crypto
import Iolaus.Database.Query
import Sthenauth.Core.Account as Account
import Sthenauth.Core.Error
import Sthenauth.Core.Policy
import Sthenauth.Core.Remote
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect

--------------------------------------------------------------------------------
data PasswordStatus
  = PasswordVerified
  | PasswordIncorrect
  deriving Show

--------------------------------------------------------------------------------
-- Verify that the given password text is strong enough to be hashed.
asStrongPassword
  :: ( Has Crypto sig m
     , Has Error  sig m
     )
  => Policy
  -> RequestTime
  -> Password Clear
  -> m (Password Strong)
asStrongPassword policy time input = do
  let zc = zxcvbnConfig policy
      p  = Crypto.toStrongPassword zc (utctDay time) input
  either (throwUserError . WeakPasswordError) pure p
  -- FIXME: validate the length of the password after it is
  -- normalized.

--------------------------------------------------------------------------------
-- | Returns 'True' if the given password matches the account.
-- Automatically upgrades the password if necessary.  May throw an
-- error directing the user to change their password.
verifyAndUpgradePassword
  :: ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => Policy
  -> RequestTime
  -> Password Clear
  -> Account
  -> m PasswordStatus
verifyAndUpgradePassword policy rtime passwd acct =
  case accountPassword acct of
    Nothing -> pure PasswordIncorrect
    Just p' -> verifyPassword passwd p' >>= \case
      PasswordMismatch ->
        pure PasswordIncorrect
      PasswordsMatch ->
        pure PasswordVerified
      PasswordNeedsUpgrade ->
        upgradePassword policy rtime passwd (accountId acct) $> PasswordVerified

--------------------------------------------------------------------------------
-- | Upgrade a password.
upgradePassword
  :: ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => Policy
  -> RequestTime
  -> Password Clear
  -> AccountId
  -> m ()
upgradePassword policy time pw aid = do
  let zc = zxcvbnConfig policy
      ps = Crypto.toStrongPassword zc (utctDay time) pw
  ps' <- either (const (throwUserError MustChangePasswordError)) pure ps
  ph <- toHashedPassword ps'
  void . transaction . update $ changePassword aid ph
