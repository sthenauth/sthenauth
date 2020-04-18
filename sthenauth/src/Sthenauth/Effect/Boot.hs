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
module Sthenauth.Effect.Boot
  ( initSthenauth
  , siteFromRemote
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Carrier.Database (Database, runDatabase)
import qualified Control.Carrier.Database as DB
import Control.Lens ((^.))
import Control.Monad.Crypto.Cryptonite (KeyManager, initCryptoniteT, fileManager)
import Iolaus.Database.Query
import qualified Paths_sthenauth as Sthenauth
import Sthenauth.Core.Config
import qualified Sthenauth.Core.Crypto as Crypto
import Sthenauth.Core.Database (runQuery)
import Sthenauth.Core.Error
import Sthenauth.Core.HTTP
import Sthenauth.Core.Remote
import Sthenauth.Core.Site
import Sthenauth.Effect.Runtime
import System.Directory
import System.FilePath
import qualified System.Metrics as Metrics

--------------------------------------------------------------------------------
initSthenauth
  :: MonadIO m
  => Config
  -> Maybe DB.Runtime
  -> Maybe KeyManager
  -> Maybe Metrics.Store
  -> m (Either Sterr Environment)
initSthenauth cfg db kmgr mstore = do
  datadir <- liftIO Sthenauth.getDataDir

  runM . runError $
    Environment
      <$> initDatabase datadir cfg db mstore
      <*> initCrypto cfg kmgr
      <*> initHTTP
      <*> pure cfg

--------------------------------------------------------------------------------
initCrypto
  :: ( MonadIO               m
     , Has (Throw Sterr) sig m
     )
  => Config
  -> Maybe KeyManager
  -> m Crypto.Runtime
initCrypto cfg mgr = do
  secretsExists <- liftIO (doesPathExist (cfg ^. secretsPath))
  when (not secretsExists && not (cfg ^. initializeMissingData)) $
    throwError (MissingSecretsDir (cfg ^. secretsPath))

  liftIO (createDirectoryIfMissing True (cfg ^. secretsPath))
  manager <- maybe (liftIO (fileManager (cfg ^. secretsPath))) pure mgr
  cryptonite <- initCryptoniteT manager

  let keys  = cfg ^. symmetricKeyLabels
      salts = cfg ^. systemSaltLabels

  Crypto.initCrypto cryptonite keys salts manager >>=
    either throwError pure

--------------------------------------------------------------------------------
-- | Initialize the database.
initDatabase
  :: (MonadIO m, Has (Throw Sterr) sig m)
  => FilePath
  -> Config
  -> Maybe DB.Runtime
  -> Maybe Metrics.Store
  -> m DB.Runtime
initDatabase datadir cfg db mstore = do
    dbrt <- connect
    runDatabase dbrt createOrMigrate $> dbrt
  where
    connect :: MonadIO m => Has (Throw Sterr) sig m => m DB.Runtime
    connect = case db of
      Just rt -> pure rt
      Nothing -> case cfg ^. databaseConfig of
        Nothing -> throwError (RuntimeError "no database configuration")
        Just c  -> DB.initRuntime c mstore

    createOrMigrate :: (Has Database sig m, Has (Throw Sterr) sig m) => m ()
    createOrMigrate
      | cfg ^. initializeMissingData = create
      | cfg ^. runDatabaseMigrations = migrate
      | otherwise                    = pass

    create :: (Has Database sig m, Has (Throw Sterr) sig m) => m ()
    create = do
      exists <- DB.migrationTableExists
      unless exists migrate
      runQuery createInitialSiteIfMissing

    migrate :: (Has Database sig m, Has (Throw Sterr) sig m) => m ()
    migrate =
      DB.migrate (datadir </> "schema") DB.MigrateVerbosely >>= \case
        DB.MigrationError e -> throwError (RuntimeError (toText e))
        DB.MigrationSuccess -> pass

--------------------------------------------------------------------------------
-- | Find a site from a remote request.
--
-- @since 0.1.0.0
siteFromRemote
  :: (Has Database sig m, Has (Throw Sterr) sig m)
  => Remote
  -> m Site
siteFromRemote remote = runQuery siteQuery where
  siteQuery :: Query Site
  siteQuery =
    select1 (siteFromFQDN (remote ^. requestFqdn)) >>= \case
      Just site -> pure site
      Nothing -> createInitialSite
