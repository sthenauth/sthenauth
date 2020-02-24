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
module Sthenauth.Core.PostLogin
  ( PostLogin(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Aeson ((.=), (.:))
import qualified Data.Aeson as Aeson
import Text.URI (URI)
import qualified Text.URI as URI

--------------------------------------------------------------------------------
-- | Information for a UI about what to do after a user logs in.
newtype PostLogin = PostLogin
  { post_login_uri :: URI
  }

instance ToJSON PostLogin where
  toJSON PostLogin{..} = Aeson.object
    [ "post_login_uri" .= URI.render post_login_uri
    ]

instance FromJSON PostLogin where
  parseJSON = Aeson.withObject "PostLogin" $ \v ->
    PostLogin <$> fmap (fromMaybe URI.emptyURI . URI.mkURI) (v .: "post_login_url")
