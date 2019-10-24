{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell            #-}

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

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Error
import Sthenauth.Types.Config (Config, databaseConfig)

--------------------------------------------------------------------------------
-- | Run-time environment.
data Env = Env
  { _config    :: Config
  , _db        :: DB.Database -- ^ The Opaleye run time.
--  , _crypto    :: Crypto.Crypto -- ^ Crypto environment.
  }

makeClassy ''Env
instance DB.HasDatabase Env where database = db
-- instance Crypto.HasCrypto Env where crypto = crypto

--------------------------------------------------------------------------------
-- | A type encapsulating Sthenauth shell commands.
newtype Command a = Command
  { unC :: ExceptT ShellError (ReaderT Env IO) a}
  deriving ( Functor, Applicative, Monad
           , MonadIO
           , MonadError ShellError
           , MonadReader Env
           )

instance DB.MonadDB Command where
  liftQuery = DB.liftQueryIO

--------------------------------------------------------------------------------
-- | Execute a 'Command'.
runCommand :: (MonadIO m) => Config -> Command a -> m (Either ShellError a)
runCommand cfg cmd =
  liftIO $ runExceptT $ do
    e <- mkEnv cfg
    mapExceptT (`runReaderT` e) (unC cmd)

  where
    mkEnv :: Config -> ExceptT ShellError IO Env
    mkEnv c =
      Env <$> pure cfg
          <*> DB.initDatabase (databaseConfig c) Nothing
          -- <*> Crypto.initCrypto _crypto
