{-# LANGUAGE FunctionalDependencies     #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

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
module Sthenauth.Shell.Command
  ( Command
  , runCommand
  , config
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Lens.TH (makeClassy)
import qualified Iolaus.Database as DB
import qualified Iolaus.Crypto as Crypto

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Error
import Sthenauth.Types.Config
import Sthenauth.Types.Secrets

--------------------------------------------------------------------------------
-- | Run-time environment.
data Env c = Env
  { _env_config  :: Config
  , _env_db      :: DB.Database -- ^ The Opaleye run time.
  , _env_crypto  :: Crypto.Crypto -- ^ Crypto environment.
  , _env_secrets :: Secrets c
  }

makeClassy ''Env

instance DB.HasDatabase (Env c) where database = env_db
instance Crypto.HasCrypto (Env c) where crypto = env_crypto
instance HasSecrets (Env c) c where secrets = env_secrets
instance HasConfig (Env c) where config = env_config

--------------------------------------------------------------------------------
-- | A type encapsulating Sthenauth shell commands.
newtype Command c a = Command
  { unC :: ExceptT ShellError (ReaderT (Env c) IO) a}
  deriving ( Functor, Applicative, Monad
           , MonadIO
           , MonadError ShellError
           , MonadReader (Env c)
           )

instance DB.MonadDB (Command c) where
  liftQuery = DB.liftQueryIO

instance Crypto.MonadCrypto (Command c) where
  liftCrypto = Crypto.runCrypto

instance MonadRandom (Command c) where
  getRandomBytes = liftIO . getRandomBytes

--------------------------------------------------------------------------------
-- | Execute a 'Command'.
runCommand
  :: (MonadIO m)
  => Config
  -> Secrets c
  -> Command c a
  -> m (Either ShellError a)
runCommand cfg sec cmd =
  liftIO $ runExceptT $ do
    e <- mkEnv cfg sec
    mapExceptT (`runReaderT` e) (unC cmd)

  where
    mkEnv :: Config -> Secrets c -> ExceptT ShellError IO (Env c)
    mkEnv c s =
      Env <$> pure cfg
          <*> DB.initDatabase (databaseConfig c) Nothing
          <*> Crypto.initCrypto
          <*> pure s
