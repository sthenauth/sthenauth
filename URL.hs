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

URL handling.

-}
module Sthenauth.Core.URL
  ( URL(..)
  , urlToText
  , urlToByteString
  , textToURL
  , strToURL
  ) where

--------------------------------------------------------------------------------
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Encoding as Aeson
import qualified Data.ByteString.Char8 as Char8
import Data.Profunctor.Product.Default (Default(def))
import Database.PostgreSQL.Simple.FromField (FromField(..))
import Network.URI (URI)
import qualified Network.URI as URI

import Opaleye
  ( Constant(..)
  , Column
  , QueryRunnerColumnDefault(..)
  , SqlText
  , fieldQueryRunnerColumn
  , toFields
  )

--------------------------------------------------------------------------------
-- | A wrapper around "Network.URI".
newtype URL = URL
  { getURI :: URI }
  deriving (Show, Eq) via URI

--------------------------------------------------------------------------------
instance ToJSON URL where
  toJSON = toJSON . urlToText
  toEncoding = Aeson.text . urlToText

instance FromJSON URL where
  parseJSON = Aeson.withText "URL" (maybe mzero pure . textToURL)

--------------------------------------------------------------------------------
instance FromField URL where
  fromField f b = fromField f b >>= (maybe mzero pure . textToURL)

instance QueryRunnerColumnDefault SqlText URL where
  queryRunnerColumnDefault = fieldQueryRunnerColumn

instance Default Constant URL (Column SqlText) where
  def = Constant (toFields . urlToText)

--------------------------------------------------------------------------------
-- | Convert a 'URL' to 'Text'.
urlToText :: URL -> Text
urlToText (URL uri) = toText (URI.uriToString id uri [])

--------------------------------------------------------------------------------
-- | Convert a 'URL' to a 'ByteString'.
urlToByteString :: URL -> ByteString
urlToByteString (URL uri) = Char8.pack (URI.uriToString id uri [])

--------------------------------------------------------------------------------
-- | Convert a 'String' value to a 'URL'.
strToURL :: MonadPlus m => String -> m URL
strToURL s = case URI.parseURI s of
  Nothing -> mzero
  Just u  -> pure (URL u)

--------------------------------------------------------------------------------
-- | Convert a 'Text' value to a 'URL'.
textToURL :: MonadPlus m => Text -> m URL
textToURL = strToURL . toString
