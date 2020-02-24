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
module Sthenauth.Providers.OIDC.Known
  ( Known
  , providerName
  , logoUrl
  , oidcUrl
  , registerUrl
  , loadKnownProviders
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Lens.TH (makeLenses)
import qualified Data.Yaml as YAML

--------------------------------------------------------------------------------
-- Package Imports:
import qualified Paths_sthenauth as Sthenauth

--------------------------------------------------------------------------------
-- | Information about a well know OIDC provider.
data Known = Known
  { _providerName :: Text
  , _logoUrl      :: Text
  , _oidcUrl      :: Text
  , _registerUrl  :: Text -- ^ Where you register for an account.
  }
  deriving stock Generic
  deriving (ToJSON, FromJSON) via GenericJSON Known

makeLenses ''Known

--------------------------------------------------------------------------------
-- | Load the known providers list from a file.
--
-- If the given path is 'Nothing', load the default providers file
-- from the Sthenauth distribution.
loadKnownProviders :: MonadIO m => Maybe FilePath -> m [Known]
loadKnownProviders (Just path) = YAML.decodeFileThrow path
loadKnownProviders Nothing = do
  dir <- liftIO Sthenauth.getDataDir
  loadKnownProviders (Just (dir </> "config" </> "oidc-providers.yml"))
