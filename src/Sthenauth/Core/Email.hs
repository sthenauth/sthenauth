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

Validated and protected email addresses.

-}
module Sthenauth.Core.Email
  ( Email
  , toEmail
  , getEmail
  , SafeEmail
  , toSafeEmail
  , fromSafeEmail
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Profunctor.Product.Default (Default(def))
import Database.PostgreSQL.Simple.FromField (FromField(..), fromJSONField)
import Iolaus.Crypto.HashedSecret (HashedSecret(..))
import Sthenauth.Crypto.Effect
import qualified Text.Email.Validate as Validate

import Opaleye
  ( QueryRunnerColumnDefault(..)
  , Constant(..)
  , Column
  , SqlJsonb
  , fieldQueryRunnerColumn
  , sqlValueJSONB
  )

--------------------------------------------------------------------------------
-- | A validated email address.
newtype Email = Email
  { getEmail :: Text
    -- ^ Extract the textual representation of an email address.
  }

--------------------------------------------------------------------------------
-- | An email address that is safe to store in the database.
newtype SafeEmail = SafeEmail { getSafeEmail :: HashedSecret Text }

instance ToJSON SafeEmail where
  toJSON = toJSON . getSafeEmail
  toEncoding = toEncoding . getSafeEmail

instance FromJSON SafeEmail where
  parseJSON = fmap SafeEmail . parseJSON

--------------------------------------------------------------------------------
instance FromField SafeEmail where
    fromField = fromJSONField

instance QueryRunnerColumnDefault SqlJsonb SafeEmail where
    queryRunnerColumnDefault = fieldQueryRunnerColumn

instance Default Constant SafeEmail (Column SqlJsonb) where
    def = Constant sqlValueJSONB

--------------------------------------------------------------------------------
-- | Validate a user-entered email address.
toEmail :: Text -> Maybe Email
toEmail text =
  -- FIXME: Temporary hack until the email-validation package properly
  -- supports Unicode email.
  Email . decodeUtf8 <$>
    Validate.canonicalizeEmail (encodeUtf8 text)

--------------------------------------------------------------------------------
-- | Prepare an email address for storage at rest.
toSafeEmail :: Has Crypto sig m => Email -> m SafeEmail
toSafeEmail (Email text) = SafeEmail <$> toHashedSecret text

--------------------------------------------------------------------------------
-- | Regain access to an encrypted email address.
fromSafeEmail :: Has Crypto sig m => SafeEmail -> m Email
fromSafeEmail (SafeEmail hs) = Email <$> decrypt (encryptedSecret hs)