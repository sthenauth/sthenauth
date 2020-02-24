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
module Sthenauth.Core.AuthN
  ( asStrongPassword
  , verifyAndUpgradePassword
  , doesAccountExist
  , getAccountFromLogin
  , accountByLogin
  , issueSession
  , resumeSession
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Time.Clock (utctDay)
import qualified Iolaus.Crypto.Password as Crypto
import Iolaus.Database.Query
import qualified Opaleye as O
import Sthenauth.Core.Account
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Core.Policy
import Sthenauth.Core.PostLogin
import Sthenauth.Core.Remote
import Sthenauth.Core.Session
import Sthenauth.Core.Site
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Providers.Local.Login

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
  -> m Bool
verifyAndUpgradePassword policy rtime passwd acct =
  case accountPassword acct of
    Nothing -> return False
    Just p' -> verifyPassword passwd p' >>= \case
      PasswordMismatch ->
        pure False
      PasswordsMatch ->
        pure True
      PasswordNeedsUpgrade ->
        upgradePassword policy rtime passwd (accountId acct) $> True

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

--------------------------------------------------------------------------------
doesAccountExist
  :: ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => SiteId
  -> Login
  -> m Bool
doesAccountExist sid l = do
  query <- accountByLogin sid l
  runQuery (count query <&> (/= 0))

--------------------------------------------------------------------------------
getAccountFromLogin
  :: ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => SiteId
  -> Login
  -> m (Maybe Account)
getAccountFromLogin sid l = do
  query <- accountByLogin sid l
  runQuery (select1 query)

--------------------------------------------------------------------------------
accountByLogin
  :: Has Crypto sig m
  => SiteId
  -> Login
  -> m (O.Query (AccountF SqlRead))
accountByLogin sid l =
  case getLogin l of
    Left  u -> pure $ query (findAccountByUsername u)
    Right e -> query . findAccountByEmail <$> toSaltedHash (getEmail e)

  where
    -- Restrict the accounts table then run a sub-query.
    query
      :: O.SelectArr (AccountF SqlRead) (AccountF SqlRead)
      -> O.Select (AccountF SqlRead)
    query sub = proc () -> do
      t1 <- fromAccounts -< ()
      O.restrict -< accountSiteId t1 .== O.toFields sid
      sub -< t1

--------------------------------------------------------------------------------
-- Issue a brand new session to the given account.
issueSession
  :: ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => Site
  -> Remote
  -> Account
  -> m (Session, ClearSessionKey, PostLogin)
issueSession site remote acct = do
  (clear, key) <- newSessionKey

  let sessionW = newSession (accountId acct) remote (sitePolicy site) key
      query = insertSession (sitePolicy site ^. maxSessionsPerAccount) sessionW
      plogin = postLogin site

  transaction query >>= \case
    Nothing -> throwError (RuntimeError "failed to create a session")
    Just session -> return (session, clear, plogin)

--------------------------------------------------------------------------------
-- | Resume an existing session.
resumeSession
  :: ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     , Has (State CurrentUser) sig m
     )
  => Site
  -> RequestTime
  -> ClearSessionKey
  -> m ()
resumeSession site rtime key = do
  user <- currentUserFromSessionKey site rtime key
  put user
