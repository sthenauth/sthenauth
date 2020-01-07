{-# LANGUAGE GeneralizedNewtypeDeriving #-}

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
  , runCommandSansAuth
  , runBootCommand
  , liftByline
  , liftSthenauth
  , config
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.Time.Clock (getCurrentTime)
import Iolaus.Crypto.Cryptonite (Cryptonite)
import qualified Iolaus.Database as DB

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Lang.Class
import Sthenauth.Lang.Script
import Sthenauth.Shell.AuthN
import Sthenauth.Shell.Byline
import Sthenauth.Shell.Error
import Sthenauth.Shell.Options (Options, site)
import qualified Sthenauth.Tables.Site as Site
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | A type encapsulating Sthenauth shell commands.
newtype Command a = Command { unC :: Script a }
  deriving ( Functor, Applicative, Monad
           , MonadIO
           , MonadError  Error
           , MonadState  Store
           , MonadReader Env
           , MonadSthenauth
           , MonadByline
           , DB.MonadDB
           , MonadCrypto Cryptonite
           , MonadRandom
           )

--------------------------------------------------------------------------------
runCommand
  :: forall m o a.
     ( MonadIO m )
  => Options o
  -> PartialEnv
  -> Command a
  -> m (Either ShellError a)
runCommand opts penv cmd =
    runCommandSansAuth opts penv go
  where
    go :: Command a
    go = do
      user <- authenticate opts
      unless (isAdmin user) (throwing _PermissionDenied ())
      cmd -- Run the original action.

--------------------------------------------------------------------------------
-- | Execute a 'Command' without authenticating first.
runCommandSansAuth
  :: forall m o a.
     ( MonadIO m )
  => Options o
  -> PartialEnv
  -> Command a
  -> m (Either ShellError a)
runCommandSansAuth opts penv cmd =
    runBootCommand opts penv (Command go)
  where
    go :: Script a
    go = withSite (site opts) $
      Site.fqdn <<$>> view env_site >>= \case
        Nothing   -> unC cmd
        Just fqdn -> local ((env_remote.request_fqdn) .~ fqdn) (unC cmd)

--------------------------------------------------------------------------------
-- | Execute a command without any authentication or database access.
runBootCommand
  :: forall m o a.
     ( MonadIO m )
  => Options o
  -> PartialEnv
  -> Command a
  -> m (Either ShellError a)
runBootCommand opts penv cmd = do
    e <- penv <$> liftIO mkRemote
    bimap SystemError fst <$> runScript e (unC cmd)

  where
    mkRemote :: IO Remote
    mkRemote = do
      rid <- genRequestId
      time <- liftIO getCurrentTime

      return Remote
        { _address      = localhost
        , _user_agent   = "Sthenauth Command Line"
        , _request_fqdn = fromMaybe "default" (site opts)
        , _request_id   = rid
        , _request_time = time
        }
