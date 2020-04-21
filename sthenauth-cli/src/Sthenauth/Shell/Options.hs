-- |
--
--
-- Copyright:
--   This file is part of the package sthenauth. It is subject to the
--   license terms in the LICENSE file found in the top-level directory
--   of this distribution and at:
--
--     https://code.devalot.com/sthenauth/sthenauth
--
--   No part of this package, including this file, may be copied,
--   modified, propagated, or distributed except according to the terms
--   contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.Shell.Options
  ( IsCommand (..),
    Options (..),
    overrideConfig,
    parseOptions,
    loadConfig,
  )
where

-- Imports:
import Control.Lens ((.~), (^.), (||~))
import qualified Data.List as List
import Data.Version (showVersion)
import qualified Data.Yaml as YAML
import Iolaus.Database.Config
import Options.Applicative
import qualified Paths_sthenauth_cli as Sthenauth
import Sthenauth.Core.Config
import System.Directory (XdgDirectoryList (..), doesFileExist, getXdgDirectoryList)
import System.Environment (getEnvironment)
import System.FilePath ((</>))

-- | Class for types that can act as a command.
class IsCommand a where
  parseCommand :: Parser a

instance IsCommand () where
  parseCommand = empty

-- | Global command line options.
data Options a = Options
  { optionsInit :: Bool,
    optionsMigrate :: Bool,
    optionsConfig :: Maybe FilePath,
    optionsDbconn :: Maybe Text,
    optionsSecrets :: Maybe FilePath,
    optionsSite :: Text,
    optionsSession :: Maybe Text,
    optionsEmail :: Maybe Text,
    optionsPassword :: Maybe Text,
    optionsCommand :: a
  }

-- | Command line parser.
parser :: IsCommand a => [(String, String)] -> Parser (Options a)
parser env =
  Options <$> optInit "INIT"
    <*> optMigrate "MIGRATE"
    <*> optional (optConfig "CONFIG")
    <*> optional (optDbconn "DB")
    <*> optional (optSecrets "SECRETS_DIR")
    <*> optSite
    <*> optSession
    <*> optional (option str (long "email" <> hidden))
    <*> optional (option str (long "password" <> hidden))
    <*> parseCommand
  where
    optInit :: String -> Parser Bool
    optInit key =
      ((not . null <$> tryEnv key) <|>) $ switch $
        mconcat
          [ short 'i',
            long "init",
            help ("Automatically initialize a new instance" <> also key)
          ]
    optMigrate :: String -> Parser Bool
    optMigrate key =
      ((not . null <$> tryEnv key) <|>) $ switch $
        mconcat
          [ short 'm',
            long "migrate",
            help ("Allow this instance to run database migrations" <> also key)
          ]
    optConfig :: String -> Parser FilePath
    optConfig key =
      (tryEnv key <|>) $ strOption $
        mconcat
          [ short 'c',
            long "config",
            metavar "FILE",
            help ("Specify the configuration file to use" <> also key)
          ]
    optDbconn :: String -> Parser Text
    optDbconn key =
      ((toText <$> tryEnv key) <|>) $ strOption $
        mconcat
          [ long "db",
            metavar "STR",
            help ("Use STR as the database connection string" <> also key)
          ]
    optSecrets :: String -> Parser String
    optSecrets key =
      (tryEnv key <|>) $ strOption $
        mconcat
          [ long "secrets",
            metavar "DIR",
            help ("Load the encryption keys from DIR" <> also key)
          ]
    optSession :: Parser (Maybe Text)
    optSession =
      optional $ option str $
        mconcat
          [ long "session",
            metavar "STR",
            help "Resume the session given in STR"
          ]
    optSite :: Parser Text
    optSite =
      option str $
        mconcat
          [ long "site",
            metavar "STR",
            value "localhost",
            help "Site FQDN, UUID, or alias FQDN"
          ]
    -- All environment variables start with this prefix:
    envPrefix :: String
    envPrefix = "STHENAUTH_"
    -- Try to extract an environment variable:
    tryEnv :: String -> Parser String
    tryEnv key = maybe empty pure (List.lookup (envPrefix <> key) env)
    also :: String -> String
    also key = " (also " <> envPrefix <> key <> ")"

-- | Override configuration options from command line or environment.
overrideConfig :: Options a -> Config -> Config
overrideConfig Options {..} config =
  config
    & databaseConfig .~ ((config ^. databaseConfig) <|> (defaultDbConfig <$> optionsDbconn))
    & secretsPath .~ fromMaybe (config ^. secretsPath) optionsSecrets
    & initializeMissingData ||~ optionsInit
    & runDatabaseMigrations ||~ optionsMigrate

-- | Execute a command line parser and return the resulting options.
parseOptions :: forall a. IsCommand a => IO (Options a)
parseOptions = do
  env <- getEnvironment
  execParser (optInfo env)
  where
    optInfo :: [(String, String)] -> ParserInfo (Options a)
    optInfo env =
      info (helper <*> optVersion <*> parser env) $
        mconcat
          [ fullDesc,
            progDesc "Run the sthenauth command COMMAND"
          ]
    optVersion =
      infoOption ("Sthenauth Version: " <> showVersion Sthenauth.version) $
        mconcat
          [ short 'V',
            long "version",
            help "Print version info and exit"
          ]

-- | Load a configuration file from disk.  If one can't be found
-- return the default configuration file.
--
-- @since 0.1.0.0
loadConfig :: forall m a. MonadIO m => Options a -> m Config
loadConfig opts =
  configDirs
    >>= load
    <&> fromMaybe (defaultConfig ".")
    <&> overrideConfig opts
  where
    configDirs :: m [FilePath]
    configDirs = do
      xdg <- liftIO (getXdgDirectoryList XdgConfigDirs)
      pure (map (</> "sthenauth") $ xdg <> ["/var/lib", "/etc"])
    load :: [FilePath] -> m (Maybe Config)
    load paths = traverse exists paths <&> asum >>= \case
      Nothing -> pure Nothing
      Just file -> liftIO (Just <$> YAML.decodeFileThrow file)
    exists :: FilePath -> m (Maybe FilePath)
    exists dir = do
      let file = dir </> "config.yml"
      e <- liftIO (doesFileExist file)
      pure $ if e then Just file else Nothing
