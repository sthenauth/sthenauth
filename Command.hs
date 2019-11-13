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
  , Env
  , HasEnv(..)
  , runCommand
  , config
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Lens.TH (makeClassy)
import Iolaus.Crypto (Crypto)
import qualified Iolaus.Crypto as Crypto
import qualified Iolaus.Database as DB
import qualified Text.Password.Strength.Config as Zxcvbn

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Error
import Sthenauth.Types.Config
import Sthenauth.Types.Secrets

--------------------------------------------------------------------------------
-- | Run-time environment.
data Env = Env
  { _env_config  :: Config
  , _env_zxcvbn  :: Zxcvbn.Config
  , _env_db      :: DB.Database -- ^ The Opaleye run time.
  , _env_crypto  :: Crypto.Crypto -- ^ Crypto environment.
  , _env_secrets :: Secrets
  }

makeClassy ''Env

instance DB.HasDatabase Env where database = env_db
instance Crypto.HasCrypto Env where crypto = env_crypto
instance HasSecrets Env where secrets = env_secrets
instance HasConfig Env where config = env_config

--------------------------------------------------------------------------------
-- | A type encapsulating Sthenauth shell commands.
newtype Command a = Command
  { unC :: ExceptT ShellError (ReaderT Env IO) a}
  deriving ( Functor, Applicative, Monad
           , MonadIO
           , MonadThrow
           , MonadCatch
           , MonadMask
           , MonadError ShellError
           , MonadReader Env
           )

instance DB.MonadDB Command where
  liftQuery = DB.liftQueryIO

instance Crypto.MonadCrypto Command where
  liftCrypto = Crypto.runCrypto

--------------------------------------------------------------------------------
-- | Execute a 'Command'.
runCommand
  :: (MonadIO m)
  => Config
  -> Secrets
  -> Crypto
  -> Command a
  -> m (Either ShellError a)
runCommand cfg sec crypto cmd =
  liftIO $ runExceptT $ do
    e <- mkEnv cfg sec
    mapExceptT (`runReaderT` e) (unC cmd)

  where
    mkEnv :: Config -> Secrets -> ExceptT ShellError IO Env
    mkEnv c s =
      Env <$> pure cfg
          <*> pure (zxcvbnConfig cfg)
          <*> DB.initDatabase (c ^. database) Nothing
          <*> pure crypto
          <*> pure s
