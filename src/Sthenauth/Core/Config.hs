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

Application-wide configuration.

-}
module Sthenauth.Core.Config
  ( Config
  , secretsPath
  , database
  , certAuth
  , symmetricKeyLabels
  , systemSaltLabels
  , baseDirectory
  , defaultConfig
  , enabledAuthenticators
  , loadConfig
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeLenses)
import Data.Aeson ((.:), (.:?), (.!=))
import qualified Data.Aeson as Aeson
import qualified Data.List.NonEmpty as NonEmpty
import qualified Data.Yaml as YAML
import Iolaus.Database.Config
import Sthenauth.CertAuth.Config (CertAuthConfig, defaultCertAuthConfig)
import Sthenauth.Core.Encoding
import Sthenauth.Core.Policy

--------------------------------------------------------------------------------
-- | Default base directory where Sthenauth will store its files.  Can
-- be overridden in the config, command line, and environment.
baseDirectory :: FilePath
baseDirectory = "/var/lib/sthenauth"

--------------------------------------------------------------------------------
-- | Configuration.
--
-- YAML/JSON keys do not include the initial underscore in the field names.
data Config = Config
  { _secretsPath :: FilePath
    -- ^ Path to the directory where secret data can be stored.

  , _database :: DbConfig
    -- ^ Settings for the @Database@ module.

  , _certAuth :: CertAuthConfig
    -- ^ Settings for the @CertAuthT@ module.

  , _symmetricKeyLabels :: NonEmpty Text
    -- ^ Labels for the symmetric keys to use, in order.

  , _systemSaltLabels :: NonEmpty Text
    -- ^ Labels for the system-wide salt values to use, in order.

  }
  deriving (Generic)
  deriving (ToJSON) via GenericJSON Config

makeLenses ''Config

--------------------------------------------------------------------------------
-- | Default configuration.
defaultConfig :: Config
defaultConfig = Config
  { _secretsPath = baseDirectory </> "secrets"
  , _database = defaultDbConfig "dbname=sthenauth"
  , _certAuth = defaultCertAuthConfig
  , _symmetricKeyLabels = "Initial Symmetric Key" :| []
  , _systemSaltLabels = "Initial System Salt" :| []
  }

--------------------------------------------------------------------------------
instance FromJSON Config where
  parseJSON = Aeson.withObject "Config" $ \v ->
    Config <$> v .:? "secrets_path" .!= _secretsPath
           <*> v .:? "database" .!= _database
           <*> v .:? "certificate_authority" .!= _certAuth
           <*> (v .: "symmetric_key_labels" <|> pure _symmetricKeyLabels)
           <*> (v .: "system_salt_labels"   <|> pure _systemSaltLabels)
    where
      Config{..} = defaultConfig

--------------------------------------------------------------------------------
-- | A list of authenticators that can actually be used in this installation.
enabledAuthenticators :: Config -> NonEmpty Authenticator
enabledAuthenticators _ = NonEmpty.fromList [MemorizedSecret]

--------------------------------------------------------------------------------
-- | Try to load the given configuration file.  Throws an IO exception
-- if there is anything wrong with the file (i.e. syntax).
loadConfig :: (MonadIO m) => FilePath -> m Config
loadConfig = YAML.decodeFileThrow
