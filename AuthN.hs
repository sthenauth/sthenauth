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
  , hashAsPassword
  , verifyPassword
  , doesAccountExist
  , getAccountFromLogin
  , accountByLogin
  , issueSession
  , resumeSession
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.Time.Clock (utctDay)
import Iolaus.Crypto
import Iolaus.Database
import Opaleye ((.==))
import qualified Opaleye as O

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Account (Account, AccountId)
import qualified Sthenauth.Tables.Account as Account
import qualified Sthenauth.Tables.Email as Email
import Sthenauth.Tables.Session (Session, ClearSessionKey)
import qualified Sthenauth.Tables.Session as Session
import Sthenauth.Tables.Site (Site, SiteId)
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Util
import Sthenauth.Types

--------------------------------------------------------------------------------
-- Verify that the given password text is strong enough to be hashed.
asStrongPassword
  :: ( MonadCrypto m
     , MonadError e m
     , MonadReader r m
     , HasConfig r
     , AsUserError e
     )
  => UTCTime
  -> Password Clear
  -> m (Password Strong)
asStrongPassword time input = do
  zc <- views config zxcvbnConfig
  p  <- strengthM zc (utctDay time) input
  either (throwing _WeakPasswordError) pure p
  -- FIXME: validate the length of the password after it is
  -- normalized.

--------------------------------------------------------------------------------
-- | Verify and has the given password.
hashAsPassword
  :: ( MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => Password Strong
  -> m (Password Hashed)
hashAsPassword input = do
  salt <- view (secrets.systemSalt)
  hash salt input

--------------------------------------------------------------------------------
-- | Returns 'True' if the given password matches the account.
-- Automatically upgrades the password if necessary.  May throw an
-- error directing the user to change their password.
verifyPassword
  :: ( MonadCrypto m
     , MonadDB m
     , MonadError e m
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     , HasSecrets r
     , HasRemote r
     )
  => Password Clear
  -> Account Id
  -> m Bool
verifyPassword p a =
  case Account.password a of
    Nothing -> return False
    Just p' -> do
      salt <- view (secrets.systemSalt)
      verify salt p p' >>= \case
        Mismatch     -> return False
        Match        -> return True
        NeedsUpgrade -> upgradePassword p (Account.pk a) >>
                        return True

--------------------------------------------------------------------------------
-- | Upgrade a password.
upgradePassword
  :: ( MonadCrypto m
     , MonadDB m
     , MonadError e m
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     , HasSecrets r
     , HasRemote r
     )
  => Password Clear
  -> AccountId
  -> m ()
upgradePassword pw aid = do
  time <- view (remote.request_time)
  salt <- view (secrets.systemSalt)
  zc <- views config zxcvbnConfig
  ps <- strengthM zc (utctDay time) pw
  ps' <- either (const $ throwing _MustChangePasswordError ()) pure ps
  ph <- hash salt ps'

  void $ liftQuery $ update $ O.Update
    { O.uTable = Account.accounts
    , uUpdateWith = O.updateEasy (\a -> a {Account.password = O.toNullable (O.toFields ph)})
    , uWhere = \a -> Account.pk a .== O.toFields aid
    , uReturning = O.rCount
    }

--------------------------------------------------------------------------------
-- FIXME: use selectFold or maybe just select the ID column.
doesAccountExist
  :: ( MonadDB m
     , MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => SiteId
  -> Login
  -> m Bool
doesAccountExist sid l = do
  query <- accountByLogin sid l

  liftQuery $ do
    n <- listToMaybe <$> select (O.countRows $ O.limit 1 query)
    pure (fromMaybe 0 n /= (0 :: Int64))

--------------------------------------------------------------------------------
getAccountFromLogin
  :: ( MonadDB m
     , MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => SiteId
  -> Login
  -> m (Maybe (Account Id))
getAccountFromLogin sid l = do
  query <- accountByLogin sid l
  listToMaybe <$> liftQuery (select $ O.limit 1 query)

--------------------------------------------------------------------------------
accountByLogin
  :: ( MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => SiteId
  -> Login
  -> m (O.Query (Account View))
accountByLogin sid l = do
  salt <- view (secrets.systemSalt)

  case getLogin l of
    Left  u -> pure $ query (Account.findAccountByUsername u)
    Right e -> query . Email.findAccountByEmail <$> saltedHash salt (getEmail e)

  where
    -- Restrict the accounts table then run a sub-query.
    query
      :: O.SelectArr (Account View) (Account View)
      -> O.Select (Account View)
    query sub = proc () -> do
      t1 <- O.selectTable Account.accounts -< ()
      O.restrict -< Account.site_id t1 .== O.toFields sid
      sub -< t1

--------------------------------------------------------------------------------
-- Issue a brand new session to the given account.
issueSession
  :: ( MonadDB m
     , MonadCrypto m
     , MonadError e m
     , AsError e
     , MonadReader r m
     , HasConfig r
     , HasRemote r
     , HasSecrets r
     )
  => Site Id
  -> Account Id
  -> m (Session Id, ClearSessionKey, PostLogin)
issueSession s a = do
  r <- view remote
  c <- view config

  (clear, key) <- Session.newSessionKey

  let sessionW = Session.newSession (Account.pk a) r (Site.policy s) key
      query = Session.insertSession (c ^. max_sessions_per_account) sessionW
      plogin = Site.postLogin s

  transaction query >>= \case
    Nothing -> throwing _RuntimeError "failed to create a session"
    Just session -> return (session, clear, plogin)

--------------------------------------------------------------------------------
-- | Resume an existing session (sets the 'currentUser' state field.)
resumeSession
  :: ( MonadDB m
     , MonadCrypto m
     , MonadReader r m
     , MaybeHasSite r
     , HasRemote r
     , HasSecrets r
     , MonadState s m
     , HasCurrentUser s
     )
  => ClearSessionKey
  -> m CurrentUser
resumeSession key = do
  user <- view maybeSite >>= \case
    Nothing   -> return notLoggedIn
    Just site -> currentUserFromSessionKey (Site.pk site) key

  assign currentUser user
  return user
