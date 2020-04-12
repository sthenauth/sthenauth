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
  ( KnownOidcProvider
  , providerName
  , logoUrl
  , discoveryUrl
  , registerUrl
  , loadKnownOidcProviders
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeLenses)
import qualified Data.Yaml as YAML
import qualified Paths_sthenauth as Sthenauth
import Sthenauth.Core.Encoding
import Sthenauth.Core.URL
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- | Information about a well know OIDC provider.
data KnownOidcProvider = KnownOidcProvider
  { _providerName :: Text
  , _logoUrl      :: URL
  , _discoveryUrl :: URL
  , _registerUrl  :: URL -- ^ Where you register for an account.
  }
  deriving stock Generic
  deriving (ToJSON, FromJSON) via GenericJSON KnownOidcProvider

makeLenses ''KnownOidcProvider

--------------------------------------------------------------------------------
-- | Load the known providers list from a file.
--
-- If the given path is 'Nothing', load the default providers file
-- from the Sthenauth distribution.
loadKnownOidcProviders :: MonadIO m => Maybe FilePath -> m [KnownOidcProvider]
loadKnownOidcProviders (Just path) = YAML.decodeFileThrow path
loadKnownOidcProviders Nothing = do
  dir <- liftIO Sthenauth.getDataDir
  loadKnownOidcProviders (Just (dir </> "config" </> "oidc-providers.yml"))
