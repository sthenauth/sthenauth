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
  , initCrypto
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Control.Carrier.Database (DatabaseC, runDatabase)
import Control.Carrier.Error.Either hiding (Error)
import Control.Carrier.Lift
import Control.Monad.Crypto.Cryptonite (KeyManager, initCryptoniteT)
import Crypto.Random (MonadRandom(..))
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Iolaus.Database.Config
import Iolaus.Database.Query (count)
import Iolaus.Database.Table (getKey)
import qualified Paths_sthenauth as Sthenauth
import Sthenauth.Core.Account as Account
import Sthenauth.Core.Admin as Admin
import Sthenauth.Core.Config
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Core.Policy (defaultPolicy)
import Sthenauth.Core.Runtime
import Sthenauth.Core.Site as Site
import Sthenauth.Crypto.Carrier (CryptoC, runCrypto)
import qualified Sthenauth.Crypto.Carrier as Crypto
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Lang.Script
import Sthenauth.Providers.Local.LocalAccount
import Sthenauth.Providers.Local.Login
import Sthenauth.Shell.Command
import Sthenauth.Shell.Helpers
import Sthenauth.Shell.IO (shellIO)
import Sthenauth.Shell.Options (Options)
import qualified Sthenauth.Shell.Options as Options
import System.Console.Byline as Byline
import System.Directory
import System.Exit (die)
import System.FilePath
import System.PosixCompat.Files (setFileMode)

--------------------------------------------------------------------------------
newtype InitC a = InitC
  { runInitC :: DatabaseC (CryptoC (ErrorC BaseError (LiftC IO))) a }
  deriving newtype (Functor, Applicative, Monad, MonadIO)

instance Algebra (Database :+: Crypto :+: Error :+: Lift IO) InitC where
    alg = InitC . alg . handleCoercible

instance MonadRandom InitC where
  getRandomBytes = randomByteArray

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
  :: (MonadIO m, Has Error sig m)
  => Options a -> m (Config, Runtime -> m ())
runInit opts = do
  dir <- shellIO Sthenauth.getDataDir
  now <- shellIO getCurrentTime

  (cfg, cmd) <-
    initConfig opts dir >>=
    (return . Options.overrideConfig opts) >>=
    initDatabase opts dir now

  let go rt = runInitC (cmd >> migrateDatabase opts dir)
            & runDatabase (rtDb rt)
            & runCrypto (rtCrypto rt)
            & runError
            & runM
            & liftIO
            & (>>= either throwError pure)

  pure (cfg, go)

--------------------------------------------------------------------------------
-- | Executed when the sthenauth subcommand is @init@.
initInteractive :: Options a -> Runtime -> IO ()
initInteractive opts renv = go >>= \case
    Left e  -> die (show e)
    Right a -> return a

  where
    go = runBootCommand opts renv $ do
      n <- runQuery (count fromAdmins)
      when (n == 0) initialAdmin

    initialAdmin :: Command ()
    initialAdmin = do
      site <- currentSite
      liftByline (sayLn ("Create the initial administrator account:" <> fg green))

      let mkLogin = toLogin . getEmail <$> maybeAskEmail (Options.email opts)
      login <- whenNothingM mkLogin (throwError (RuntimeError "invalid email address"))
      ps <- snd <$> maybeAskNewPassword (sitePolicy site) (Options.password opts)
      ph <- toHashedPassword ps

      la <- toLocalAccount (Site.siteId site) login ph

      madmin <- transaction $ do
        acct <- insertLocalAccountQuery la
        insertAdmin (Account.accountId acct)

      case madmin of
        Nothing -> throwError (RuntimeError "failed to create admin account")
        Just admin -> liftIO $
          putTextLn $ "New account ID: " <>
                      UUID.toText (getKey $ Admin.adminAccountId admin)

--------------------------------------------------------------------------------
initCrypto
  :: ( MonadIO        m
     , Has Error  sig m
     )
  => Options a
  -> Config
  -> KeyManager
  -> m Crypto.Runtime
initCrypto options cfg mgr = do
  secretsExists <- liftIO (doesPathExist (cfg ^. secretsPath))

  when (not secretsExists && not (Options.init options)) $
    throwError (MissingSecretsDir (cfg ^. secretsPath))

  liftIO (createDirectoryIfMissing True (cfg ^. secretsPath))
  cryptonite <- initCryptoniteT mgr

  let keys  = cfg ^. symmetricKeyLabels
      salts = cfg ^. systemSaltLabels

  Crypto.initCrypto cryptonite keys salts mgr >>=
    either throwError pure

--------------------------------------------------------------------------------
-- | Create a configuration file if it doesn't exist, then load it.
initConfig
  :: forall sig m a.
  (MonadIO m, Has Error sig m)
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
        else throwError (MissingDefaultConfigError src dst)

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
    newConfigOrDefault src = catchError (newConfig src) onError
      where
        onError :: BaseError -> m Config
        onError (ShellException _) = loadConfig src
        onError otherError         = throwError otherError

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
  :: Monad m
  => Options a
  -> FilePath
  -> UTCTime
  -> Config
  -> m (Config, InitC ())
initDatabase opts dataDir now cfg = do
  let conn = maybe (cfg ^. database.databaseConnectionString) toText $ Options.dbconn opts
      cfg' = cfg & (database.databaseConnectionString) .~ conn

  pure (cfg', go)

  where
    go :: InitC ()
    go = when (Options.init opts) $ do
      exists <- migrationTableExists
      unless exists (migrateDatabase opts dataDir)
      siteQuery

    siteQuery :: InitC ()
    siteQuery = do
      let site = Site
            { siteId        = mempty
            , siteCreatedAt = mempty
            , siteUpdatedAt = mempty
            , siteIsDefault = Just True
            , afterLoginUrl = Nothing
            , siteFqdn      = "localhost"
            , sitePolicy    = defaultPolicy
            }
      whenM (runQuery (count defaultSite <&> (== 0)))
        (void $ createSite now site)

--------------------------------------------------------------------------------
-- | Return a 'Command' that can be used to migrate the database.
migrateDatabase
  :: Options a
  -> FilePath
  -> InitC ()
migrateDatabase opts dataDir = when (Options.migrate opts) $
  migrate (dataDir </> "schema") MigrateVerbosely >>= \case
    MigrationError e -> throwError (RuntimeError (toText e))
    MigrationSuccess -> pass
