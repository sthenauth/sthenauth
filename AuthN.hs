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
  ( doesAccountExist
  , accountByLogin
  ) where


--------------------------------------------------------------------------------
-- Library Imports:
import Control.Arrow (returnA)
import Iolaus.Crypto (MonadCrypto)
import qualified Iolaus.Crypto as Crypto
import Iolaus.Opaleye
import Opaleye ((.==))
import qualified Opaleye as O

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Account (Account)
import qualified Sthenauth.Tables.Account as Account
import qualified Sthenauth.Tables.Email as Email
import Sthenauth.Tables.Util
import Sthenauth.Types.Email
import Sthenauth.Types.Login hiding (login)
import Sthenauth.Types.Secrets
import Sthenauth.Types.Username

--------------------------------------------------------------------------------
-- FIXME: use selectFold or maybe just select the ID column.
doesAccountExist
  :: ( MonadOpaleye m
     , MonadCrypto m
     , MonadReader r m
     , HasSecrets r c
     )
  => Login
  -> m Bool
doesAccountExist login = do
  query <- accountByLogin login

  liftQuery $ do
    n <- listToMaybe <$> select (O.countRows $ O.limit 1 query)
    pure (fromMaybe 0 n /= (0 :: Int64))

--------------------------------------------------------------------------------
accountByLogin
  :: ( MonadCrypto m
     , MonadReader r m
     , HasSecrets r c
     )
  => Login
  -> m (O.Query (Account View))
accountByLogin login = do
  salt <- view (secrets.systemSalt)

  case getLogin login of
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
