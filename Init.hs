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
  , initInteractive
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.Time.Clock (getCurrentTime)
import qualified Iolaus.Database as DB
import qualified Opaleye as O
import System.Console.Byline as Byline
import System.Directory
import System.Exit (die)
import System.FilePath
import qualified Data.UUID as UUID
import System.PosixCompat.Files (setFileMode)

--------------------------------------------------------------------------------
-- Project Imports:
import qualified Paths_sthenauth as Sthenauth
import qualified Sthenauth.Core.Admin as Core
import qualified Sthenauth.Core.AuthN as Core
import Sthenauth.Lang.Script
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.Command
import Sthenauth.Shell.Error
import Sthenauth.Shell.IO (shellIO)
import Sthenauth.Shell.Options (Options)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Tables.Admin as Admin
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Account as Account
import Sthenauth.Tables.Util (count, getKey)
import Sthenauth.Types

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
  :: ( MonadIO m
     , MonadCrypto m
     , MonadError e m
     , AsShellError e
     )
  => Options a
  -> m (Config, Command ())
runInit opts = do
  dir <- shellIO Sthenauth.getDataDir
  now <- shellIO getCurrentTime

  (cfg, cmd) <-
    initConfig opts dir >>=
    initSecrets opts    >>=
    initDatabase opts dir now

  pure (cfg, cmd >> migrateDatabase opts dir)

--------------------------------------------------------------------------------
-- | Executed when the sthenauth subcommand is @init@.
initInteractive :: Options a -> PartialEnv -> IO ()
initInteractive opts penv = go >>= \case
    Left e  -> die (show e)
    Right a -> return a

  where
    go = runCommandSansAuth opts penv $ do
      n <- liftQuery $ count (O.limit 1 $ O.selectTable admins)
      when (n == 0) initialAdmin

    initialAdmin :: Command ()
    initialAdmin = do
      site <- whenNothingM (view env_site) (throwing _MissingSiteError ())

      liftByline (sayLn ("Create the initial administrator account:" <> fg green))

      let mkLogin = toLogin . getEmail <$> maybeAskEmail (Options.email opts)
      login <- whenNothingM mkLogin (throwing _RuntimeError "invalid email address")
      ps <- snd <$> maybeAskNewPassword (Options.password opts)
      ph <- Core.hashAsPassword ps

      la <- toLocalAccount (Site.pk site) login ph

      madmin <- DB.transaction $
        insertLocalAccountQuery la >>= \case
          Nothing -> return Nothing
          Just a  -> insertAdmin (Account.pk a)

      case madmin of
        Nothing -> throwing _RuntimeError "failed to create admin account"
        Just admin -> liftIO $
          putTextLn $ "New account ID: " <>
                      UUID.toText (getKey $ Admin.account_id admin)

--------------------------------------------------------------------------------
-- | Create a configuration file if it doesn't exist, then load it.
initConfig
  :: forall e m a.
  ( MonadIO m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> FilePath
  -> m Config
initConfig options dataDir = do
  exists <- shellIO $ doesFileExist (Options.config options)

  if | exists -> loadConfig (Options.config options)
     | Options.init options -> withDefaultConfig newConfigOrDefault
     | otherwise -> withDefaultConfig loadConfig

  where
    -- Do something with the default configuration file.
    withDefaultConfig :: (FilePath -> m b) -> m b
    withDefaultConfig f = do
      let src = dataDir </> "config" </> "default.yml"
          dst = Options.config options

      exists <- shellIO $ doesFileExist src

      if exists
        then f src
        else throwing _MissingDefaultConfig (src, dst)

    -- Create a new configuration file by copying the default file.
    newConfig :: FilePath -> m Config
    newConfig src = do
      let dst = Options.config options
      shellIO $ do
        createDirectoryIfMissing True (takeDirectory dst)
        copyFile src dst
        setFileMode dst 0o600 -- copyFile doesn't respect umask
      loadConfig dst

    -- Try to create a new config file.  If that fails just load the
    -- default file instead.
    newConfigOrDefault :: FilePath -> m Config
    newConfigOrDefault src =
      catching _ShellException
        (newConfig src) (const (loadConfig src))

--------------------------------------------------------------------------------
-- | Create a new keys file if one doesn't already exist.
initSecrets
  :: forall e m a.
  ( MonadIO m
  , MonadCrypto m
  , MonadError e m
  , AsShellError e
  )
  => Options a
  -> Config
  -> m Config
initSecrets options cfg = do
  let src  = Options.secrets options <|> cfg ^. secrets_path
      def  = Options.private options </> "secrets.json"
      path = fromMaybe def src

  exists <- shellIO (doesFileExist path)

  if | exists -> done path
     | Options.init options -> go path >> done path
     | otherwise -> throwing _MissingSecretsFile path

  where
    go :: FilePath -> m ()
    go file = do
      shellIO (createDirectoryIfMissing True (takeDirectory file))
      s <- generateSecrets
      saveSecretsFile file s

    done :: FilePath -> m Config
    done path = pure (cfg & secrets_path ?~ path)

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
  :: forall m a. (Monad m)
  => Options a
  -> FilePath
  -> UTCTime
  -> Config
  -> m (Config, Command ())
initDatabase opts dataDir now cfg = do
  let def = cfg ^. database
      conn = maybe (DB.connectionString def) toText $ Options.dbconn opts
      cfg' = cfg & database .~ (def { DB.connectionString = conn })

  pure (cfg', go)

  where
    go :: Command ()
    go = when (Options.init opts) $ do
      exists <- DB.initialized
      unless exists (DB.migrate (dataDir </> "schema") True)
      siteQuery

    siteQuery :: Command ()
    siteQuery = do
      sec  <- view secrets

      let site = Site { pk = mempty
                      , created_at = mempty
                      , updated_at = mempty
                      , is_default = Just True
                      , after_login_url = Nothing
                      , fqdn = "localhost"
                      , policy = defaultPolicy
                      }
      whenNothingM_ Site.selectDefaultSite
        (void $ Core.createSite now sec site)


--------------------------------------------------------------------------------
-- | Return a 'Command' that can be used to migrate the database.
migrateDatabase
  :: Options a
  -> FilePath
  -> Command ()
migrateDatabase opts dataDir = when (Options.migrate opts) $
  DB.migrate (dataDir </> "schema") True
