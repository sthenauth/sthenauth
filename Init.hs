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

Special command that can bootstrap sthenauth from nothing.

-}
module Sthenauth.Shell.Init
  ( runInit
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Iolaus.Crypto (DefaultCipher)
import qualified Iolaus.Opaleye as DB
import System.Directory
import System.FilePath
import System.PosixCompat.Files (setFileMode)

--------------------------------------------------------------------------------
-- Project Imports:
import qualified Paths_sthenauth as Sthenauth
import Sthenauth.Shell.Command
import Sthenauth.Shell.Error
import Sthenauth.Shell.IO (shellIO)
import Sthenauth.Shell.Options (Options)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Types.Config
import Sthenauth.Types.Secrets

--------------------------------------------------------------------------------
-- | Initialize the application in preparation for running a command.
--
-- Actions taken:
--
--   1. Evaluate all sources of configuration and merge them into a
--      single configuration.
--
--   2. Construct a 'Command' that initializes the database, if the
--      given 'Options' allow doing so.
--
runInit
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> m (Config, Command ())
runInit opts = do
  (cfg, cmd) <- initConfig opts >>=
                  initSecrets opts >>=
                  initDatabase opts

  pure (cfg, cmd >> migrateDatabase opts)

--------------------------------------------------------------------------------
-- | Create a configuration file if it doesn't exist, then load it.
initConfig
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> m Config
initConfig options = do
  exists <- shellIO $ doesFileExist (Options.config options)

  if | exists -> loadConfig (Options.config options)
     | Options.init options -> newConfig
     | otherwise -> throwing _MissingConfig (Options.config options)

  where
    newConfig :: m Config
    newConfig = do
      defaults <- shellIO Sthenauth.getDataDir

      let src = defaults </> "config" </> "default.config"
          dst = Options.config options

      exists <- shellIO $ doesFileExist src

      if exists
        then copyConfig src dst >> loadConfig dst
        else throwing _MissingDefaultConfig (src, dst)

    copyConfig :: FilePath -> FilePath -> m ()
    copyConfig src dst = shellIO $ do
      createDirectoryIfMissing True (takeDirectory dst)
      copyFile src dst
      setFileMode dst 0o600 -- copyFile doesn't respect umask

--------------------------------------------------------------------------------
-- | Create a new keys file if one doesn't already exist.
initSecrets
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> Config
  -> m Config
initSecrets options cfg = do
  let src  = Options.secrets options <|> cfg ^. secretsPath
      def  = Options.private options </> "secrets.json"
      path = fromMaybe def src

  exists <- shellIO (doesFileExist path)

  if | exists -> done path
     | Options.init options -> go path >> done path
     | otherwise -> throwing _MissingSecretsFile path

  where
    go :: FilePath -> m ()
    go file =
      shellIO (generateSecrets :: IO (Secrets DefaultCipher)) >>=
        saveSecretsFile file

    done :: FilePath -> m Config
    done path = pure (cfg & secretsPath ?~ path)

--------------------------------------------------------------------------------
-- | Initialize the database.
--
-- Extract the database configuration from the given 'Config' value
-- and override the database connection string from the command line
-- or environment if requested.
--
-- Returns the updated 'Config' and a 'Command' that can be used to
-- initialize the database.
initDatabase
  :: (Monad m)
  => Options a
  -> Config
  -> m (Config, Command ())
initDatabase opts cfg = do
  let def = databaseConfig cfg
      conn = maybe (DB.connectionString def) toText $ Options.dbconn opts
      cfg' = cfg & database ?~ (def { DB.connectionString = conn })

  pure (cfg', go)

  where
    go :: Command ()
    go = when (Options.init opts) $ do
      schemaDir <- (</> "schema") <$> shellIO Sthenauth.getDataDir
      exists <- DB.initialized
      unless exists (DB.migrate schemaDir True)

--------------------------------------------------------------------------------
-- | Return a 'Command' that can be used to migrate the database.
migrateDatabase
  :: Options a
  -> Command ()
migrateDatabase opts = when (Options.migrate opts) $ do
  schemaDir <- (</> "schema") <$> shellIO Sthenauth.getDataDir
  DB.migrate schemaDir True
