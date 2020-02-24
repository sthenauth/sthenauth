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
module Sthenauth.Providers.Local.Login
  ( Login
  , getLogin
  , toLogin

  , SafeLogin
  , toSafeLogin
  , fromSafeLogin

  , Credentials(..)
  , fromCredentials
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Profunctor.Product.Default (Default(def))
import Database.PostgreSQL.Simple.FromField (FromField(..), fromJSONField)
import Iolaus.Crypto.HashedSecret (HashedSecret(..))
import Iolaus.Crypto.Password
import Sthenauth.Crypto.Effect
import Sthenauth.Core.Email
import Sthenauth.Core.Username

import Opaleye
  ( QueryRunnerColumnDefault(..)
  , Constant(..)
  , Column
  , SqlJsonb
  , fieldQueryRunnerColumn
  , sqlValueJSONB
  )

--------------------------------------------------------------------------------
-- | A customer can identify themselves with either a username or an
-- email address.  The 'Login' type realizes this connection.
newtype Login = Login { getLogin :: Either Username Email }

instance ToSafe Login where
  type SafeT Login = SafeLogin
  toSafe = toSafeLogin

--------------------------------------------------------------------------------
-- | Create a 'Login' from customer-supplied text.
toLogin :: Text -> Maybe Login
toLogin text = Login <$>
  case toEmail text of
    Nothing -> Left <$> toUsername text
    Just e  -> Just (Right e)

--------------------------------------------------------------------------------
-- | A variant of 'Login' that is safe to store in a database or
-- export to a remote system.
newtype SafeLogin = SafeLogin { getSafeLogin :: HashedSecret Text }

instance ToJSON SafeLogin where
  toJSON = toJSON . getSafeLogin
  toEncoding = toEncoding . getSafeLogin

instance FromJSON SafeLogin where
  parseJSON = fmap SafeLogin . parseJSON

instance FromField SafeLogin where
    fromField = fromJSONField

instance QueryRunnerColumnDefault SqlJsonb SafeLogin where
    queryRunnerColumnDefault = fieldQueryRunnerColumn

instance Default Constant SafeLogin (Column SqlJsonb) where
    def = Constant sqlValueJSONB

--------------------------------------------------------------------------------
-- | Convert a 'Login' to a 'SafeLogin'.
toSafeLogin :: Has Crypto sig m => Login -> m SafeLogin
toSafeLogin (Login l) = do
  let text = either getUsername getEmail l
  SafeLogin <$> toHashedSecret text

--------------------------------------------------------------------------------
-- | Extract the original user input from a 'SafeLogin'.
fromSafeLogin :: Has Crypto sig m => SafeLogin -> m Text
fromSafeLogin (SafeLogin hs) = decrypt (encryptedSecret hs)

--------------------------------------------------------------------------------
-- | Login credentials.
data Credentials = Credentials
  { name     :: Text -- ^ Username or email address.
  , password :: Text -- ^ Clear text password.
  } deriving (Generic, FromJSON)

--------------------------------------------------------------------------------
-- | Turn credentials into a 'Login' and 'Password' pair.
fromCredentials :: Credentials -> Maybe (Login, Password Clear)
fromCredentials Credentials{..} = (,toPassword password) <$> toLogin name
