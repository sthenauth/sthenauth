{-# LANGUAGE GeneralizedNewtypeDeriving #-}

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
module Sthenauth.Shell.Boot
  ( run
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Options.Applicative
import System.Exit (die)
import System.PosixCompat.Files (setFileCreationMask)
import Iolaus.Crypto (Crypto, initCrypto, runCrypto)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command (Command, runCommand)
import Sthenauth.Shell.Error
import Sthenauth.Shell.Init
import Sthenauth.Shell.Options (Options, IsCommand(..), parse)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Types.Config
import Sthenauth.Types.Secrets

--------------------------------------------------------------------------------
-- | Sub-commands:
import qualified Sthenauth.Shell.Admin as Admin
import qualified Sthenauth.Shell.Info as Info
import qualified Sthenauth.Shell.Server as Server

--------------------------------------------------------------------------------
-- | The various commands that can be executed.
data Commands
  = InfoCommand
  | ServerCommand
  | AdminCommand Admin.Action

--------------------------------------------------------------------------------
-- Command line parser for each command.
instance IsCommand Commands where
  parseCommand = hsubparser $
    mconcat [ cmd "info" "Display evaluated config" (pure InfoCommand)
            , cmd "server" "Start the HTTP server" (pure ServerCommand)
            , cmd "admin" "Manage admin accounts" (AdminCommand <$> Admin.options)
            ]
    where
      cmd :: String -> String -> Parser a -> Mod CommandFields a
      cmd name desc p = command name (info p (progDesc desc))

--------------------------------------------------------------------------------
newtype Boot a = Boot
  { runBoot :: ExceptT ShellError (ReaderT Crypto IO) a }
  deriving ( Functor, Applicative, Monad, MonadIO
           , MonadError ShellError
           , MonadReader Crypto
           )

instance MonadCrypto Boot where
  liftCrypto = runCrypto

--------------------------------------------------------------------------------
-- | Main entry point.
run :: IO ()
run = do
  -- General process settings:
  void (setFileCreationMask 0o077)

  -- Option parsing and processing:
  options <- parse :: IO (Options Commands)

  -- FIXME: We need a way to make the block cipher selectable at run time.
  crypto <- initCrypto

  (cfg, initcmd, sec) <-
    usingReaderT crypto (runExceptT (runBoot $ boot options)) >>=
    checkOrDie

  let cmd = case Options.command options of
             InfoCommand -> Info.run options
             ServerCommand -> Server.run options
             AdminCommand o -> Admin.run o

  runCommand cfg sec crypto (initcmd >> cmd) >>= checkOrDie

  where
    checkOrDie :: Either ShellError a -> IO a
    checkOrDie (Right a) = pure a
    checkOrDie (Left e)  = die (show e)

    boot :: Options Commands -> Boot (Config, Command (), Secrets)
    boot options = do
      (cfg, cmd) <- runInit options
      sec <- loadSecretsFile $ fromMaybe "/dev/null" (cfg ^. secrets_path)
      return (cfg, cmd, sec)
