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
  , symmetricKeyLabels
  , systemSaltLabels
  , defaultConfig
  , enabledAuthenticators
  , initializeMissingData
  , runDatabaseMigrations
  , databaseConfig
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeLenses)
import qualified Data.List.NonEmpty as NonEmpty
import Iolaus.Database.Config (DbConfig)
import Sthenauth.Core.Encoding
import Sthenauth.Core.Policy
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- | Configuration.
--
-- YAML/JSON keys do not include the initial underscore in the field names.
data Config = Config
  { _secretsPath :: FilePath
    -- ^ Path to the directory where secret data can be stored.

  , _symmetricKeyLabels :: NonEmpty Text
    -- ^ Labels for the symmetric keys to use, in order.

  , _systemSaltLabels :: NonEmpty Text
    -- ^ Labels for the system-wide salt values to use, in order.

  , _initializeMissingData :: Bool
    -- ^ Allow this instance of Sthenauth to initialize sub-systems as
    -- necessary (e.g., create database tables, create new encryption
    -- keys, etc.)
    --
    -- This should only be enabled on a single running instance to
    -- avoid multi-process race conditions.
    --
    -- If this option is enabled then '_runDatabaseMigrations' is
    -- automatically enabled too.

  , _runDatabaseMigrations :: Bool
    -- ^ Similar to '_initializeMissingData', this option controls
    -- whether or not the database will be checked for out of date
    -- migrations and upgraded automatically.
    --
    -- You probably want this option to always be turned on, but like
    -- '_initializeMissingData', only for a single process.

  , _databaseConfig :: Maybe DbConfig
    -- ^ Optional database configuration.
  }
  deriving (Generic)
  deriving (ToJSON, FromJSON) via GenericJSON Config

makeLenses ''Config

--------------------------------------------------------------------------------
-- | Default configuration.
defaultConfig :: FilePath -> Config
defaultConfig baseDirectory = Config
  { _secretsPath = baseDirectory </> "secrets"
  , _symmetricKeyLabels = "Initial Symmetric Key" :| []
  , _systemSaltLabels = "Initial System Salt" :| []
  , _initializeMissingData = True
  , _runDatabaseMigrations = True
  , _databaseConfig = Nothing
  }

--------------------------------------------------------------------------------
-- | A list of authenticators that can actually be used in this installation.
enabledAuthenticators :: Config -> NonEmpty Authenticator
enabledAuthenticators _ = NonEmpty.fromList [MemorizedSecret]
