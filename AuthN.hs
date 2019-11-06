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
  , doesAccountExist
  , accountByLogin
  ) where


--------------------------------------------------------------------------------
-- Library Imports:
import Control.Arrow (returnA)
import Data.Time.Clock (utctDay)
import Iolaus.Crypto (MonadCrypto)
import qualified Iolaus.Crypto as Crypto
import Iolaus.Database
import Opaleye ((.==))
import qualified Opaleye as O

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Account (Account)
import qualified Sthenauth.Tables.Account as Account
import qualified Sthenauth.Tables.Email as Email
import Sthenauth.Tables.Util
import Sthenauth.Types hiding (Address, getAddress)
import Sthenauth.Types.Email

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
  -> Text
  -> m (Crypto.Password Crypto.Strong)
asStrongPassword time input = do
  zc <- views config zxcvbnConfig
  p  <- Crypto.password input >>= Crypto.strength zc (utctDay time)
  either (throwing _WeakPasswordError) pure p

--------------------------------------------------------------------------------
-- | Verify and has the given password.
hashAsPassword
  :: ( MonadCrypto m
     , MonadError e m
     , MonadReader r m
     , HasSecrets r
     , HasConfig r
     , AsUserError e
     )
  => UTCTime
  -> Text
  -> m (Crypto.Password Crypto.Hashed)
hashAsPassword time input = do
  salt <- view (secrets.systemSalt)
  p <- asStrongPassword time input
  Crypto.hash salt p

--------------------------------------------------------------------------------
-- FIXME: use selectFold or maybe just select the ID column.
doesAccountExist
  :: ( MonadDB m
     , MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => Login
  -> m Bool
doesAccountExist l = do
  query <- accountByLogin l

  liftQuery $ do
    n <- listToMaybe <$> select (O.countRows $ O.limit 1 query)
    pure (fromMaybe 0 n /= (0 :: Int64))

--------------------------------------------------------------------------------
accountByLogin
  :: ( MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => Login
  -> m (O.Query (Account View))
accountByLogin l = do
  salt <- view (secrets.systemSalt)

  case getLogin l of
    Left  u -> pure $ byUsername u
    Right a -> byAddress <$> Crypto.saltedHash salt (getAddress a)

  where
    -- Find an account with a username.
    byUsername :: Username -> O.Query (Account View)
    byUsername u = proc () -> do
      a <- O.selectTable Account.accounts -< ()

      O.restrict -< O.matchNullable
                      (O.sqlBool False)
                      (`lowerEq` getUsername u)
                      (Account.username a)
      returnA -< a

    -- Find an account based on an email address.
    byAddress :: Crypto.SaltedHash Text -> O.Query (Account View)
    byAddress hash = proc () -> do
      a <- O.selectTable Account.accounts -< ()
      e <- O.selectTable Email.emails -< ()

      O.restrict -< Email.emailHashed e .== O.toNullable (sqlValueJSONB hash)
      returnA -< a
