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
module Sthenauth.Core.Username
  ( Username
  , toUsername
  , getUsername
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.Profunctor.Product.Default (Default(def))
import Data.Text (strip, toLower)
import qualified Data.Text as Text
import Data.Text.ICU.Normalize (NormalizationMode(NFKC), normalize)
import Database.PostgreSQL.Simple.FromField (FromField(..))
import Sthenauth.Core.Email

import Opaleye
  ( Constant(..)
  , Column
  , QueryRunnerColumnDefault(..)
  , SqlText
  , fieldQueryRunnerColumn
  , toFields
  )

--------------------------------------------------------------------------------
-- | Type representing a normalized user name.
newtype Username = Username
  { getUsername :: Text -- ^ Extract a normalized user name.
  }

--------------------------------------------------------------------------------
-- | Create a username from 'Text'.
toUsername :: Text -> Maybe Username
toUsername dirty =
  let t = clean dirty
  in if validate t then Just (Username t) else Nothing

--------------------------------------------------------------------------------
validate :: Text -> Bool
validate t =
  not (Text.null t) &&
  Text.compareLength t 256 == LT &&
  isNothing (toEmail t)

--------------------------------------------------------------------------------
clean :: Text -> Text
clean = toLower . normalize NFKC . strip

--------------------------------------------------------------------------------
-- So we can store user names in the database transparently.
instance FromField Username where
  fromField f b = Username . clean <$> fromField f b

instance QueryRunnerColumnDefault SqlText Username where
  queryRunnerColumnDefault = fieldQueryRunnerColumn

instance Default Constant Username (Column SqlText) where
  def = Constant (toFields . getUsername)
