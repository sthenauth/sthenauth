{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell            #-}

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

-}
module Sthenauth.API.Monad
  ( runRequest
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Lens.TH (makeLenses)
import qualified Iolaus.Crypto as Crypto
import qualified Iolaus.Database as DB
import Servant.Server

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.API.Log
import Sthenauth.API.Middleware (Client)
import qualified Sthenauth.Core.Admin as Core
import Sthenauth.Lang.Interpreter (eval)
import Sthenauth.Lang.Sthenauth (Sthenauth)
import qualified Sthenauth.Shell.Command as Command
import Sthenauth.Tables.Site (Site, MaybeHasSite(..))
import Sthenauth.Tables.Util (Id)
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Reader environment.
data Env = Env
  { _env_config :: Config
  , _env_db :: DB.Database
  , _env_crypto :: Crypto.Crypto
  , _env_secrets :: Secrets
  , _env_remote :: Remote
  , _env_site :: Maybe (Site Id)
  }

makeLenses ''Env

instance HasConfig Env where config = env_config
instance DB.HasDatabase Env where database = env_db
instance Crypto.HasCrypto Env where crypto = env_crypto
instance HasSecrets Env where secrets = env_secrets
instance HasRemote Env where remote = env_remote
instance MaybeHasSite Env where maybeSite = env_site

--------------------------------------------------------------------------------
-- | State.
newtype Store = Store
  { _state_user :: CurrentUser
  }

makeLenses ''Store

instance HasCurrentUser Store where currentUser = state_user

--------------------------------------------------------------------------------
-- | The main monad transformer stack.
newtype App a = App
  { runApp :: ExceptT Error (StateT Store (ReaderT Env IO)) a}
  deriving ( Functor, Applicative, Monad
           , MonadIO
           , MonadError Error
           , MonadState Store
           , MonadReader Env
           )

instance DB.MonadDB App where
  liftQuery = DB.liftQueryIO

instance Crypto.MonadCrypto App where
  liftCrypto = Crypto.runCrypto

--------------------------------------------------------------------------------
-- | Execute a 'Sthenauth' action, producing a Servant @Handler@.
runRequest
  :: forall a. Command.Env
  -> Client
  -> Logger
  -> Sthenauth a
  -> Handler a
runRequest e client l s = do
  (result, store') <-
    liftIO $ usingReaderT env $ usingStateT store $ runExceptT (runApp enter)

  case result of
    Right a  -> leave a store'
    Left  e' -> do
      liftIO (logger_error l (fst client) (show e' :: Text))
      throwError (toServerError e')

  where
    -- Prepare and then execute the request.
    enter :: App a
    enter = do
      site <- Core.siteFromRemote (fst client)
      whenJust (snd client) (currentUserFromSessionKey >=> assign state_user)
      local (env_site .~ site) (eval s)

    -- Actions to run after the request is done.
    leave :: a -> Store -> Handler a
    leave a _ = pure a

    env :: Env
    env =
      Env { _env_config = e ^. Command.env_config
          , _env_db = e ^. Command.env_db
          , _env_crypto = e ^. Command.env_crypto
          , _env_secrets = e ^. Command.env_secrets
          , _env_remote = (fst client)
          , _env_site = Nothing
          }

    store :: Store
    store =
      Store { _state_user = notLoggedIn
            }
