{-# LANGUAGE MultiWayIf          #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
import Control.Applicative
import Control.Lens ((&), (?~))
import Control.Monad (when, unless)
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except (MonadError)
import Control.Monad.IO.Class (MonadIO)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import qualified Iolaus.Crypto.Key as Key
import qualified Iolaus.Crypto.Salt as Salt
import qualified Iolaus.Opaleye as DB
import System.Directory
import System.FilePath

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.IO (shellIO)
import qualified Paths_sthenauth as Sthenauth
import Sthenauth.Types.Config
import Sthenauth.Shell.Options (Options)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Shell.Command
import Sthenauth.Shell.Error

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
  (cfg, cmd) <- initConfig opts         >>=
                  initSymmetricKey opts >>=
                  initSystemSalt opts   >>=
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

--------------------------------------------------------------------------------
-- | Create a new symmetric key if one doesn't already exist.
initSymmetricKey
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> Config
  -> m Config
initSymmetricKey options cfg = do
  let src  = Options.skeypath options <|> _symmetricKeyPath cfg
      def  = Options.private options </> "skey.txt"
      path = fromMaybe def src

  exists <- makeFile options path (Key.encode <$> Key.generate)

  if exists
    then pure (cfg & symmetricKeyPath ?~ path)
    else throwing _MissingSymmetricKey path

--------------------------------------------------------------------------------
-- | Create a new system salt file if one doesn't already exist.
initSystemSalt
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> Config
  -> m Config
initSystemSalt opts cfg = do
  let src  = Options.saltpath opts <|> _systemSaltPath cfg
      def  = Options.private opts </> "salt.txt"
      path = fromMaybe def src

  exists <- makeFile opts path (Salt.encode <$> Salt.generate)

  if exists
    then pure (cfg & systemSaltPath ?~ path)
    else throwing _MissingSystemSalt path

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
      conn = maybe (DB.connectionString def) Text.pack $ Options.dbconn opts
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

--------------------------------------------------------------------------------
-- | Create a file if it doesn't exist and we're in @init@ mode.
makeFile
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> FilePath   -- ^ The file to create if it's missing.
  -> IO Text    -- ^ Action to produce the file's content.
  -> m Bool     -- ^ True if the file exists or was created.
makeFile opts path action = do
  exists <- shellIO (doesFileExist path)

  if | exists -> pure True
     | Options.init opts -> createFile
     | otherwise -> pure False

  where
    createFile :: m Bool
    createFile = shellIO $ do
      createDirectoryIfMissing True (takeDirectory path)
      action >>= Text.writeFile path
      doesFileExist path
