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
import Iolaus.Crypto.Cryptonite
import qualified Iolaus.Database as DB
import Options.Applicative
import System.Exit (die)
import System.PosixCompat.Files (setFileCreationMask)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command
import Sthenauth.Shell.Error
import Sthenauth.Shell.Init
import Sthenauth.Shell.Options (Options, IsCommand(..), parse)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Types
import Sthenauth.Lang.Script

--------------------------------------------------------------------------------
-- Sub-commands:
import qualified Sthenauth.Shell.Admin as Admin
import qualified Sthenauth.Shell.Info as Info
import qualified Sthenauth.Shell.Policy as Policy
import qualified Sthenauth.Shell.Server as Server

--------------------------------------------------------------------------------
-- | The various commands that can be executed.
data Commands
  = InitCommand
  | ServerCommand
  | InfoCommand
  | PolicyCommand Policy.SubCommand
  | AdminCommand Admin.Action

--------------------------------------------------------------------------------
-- Command line parser for each command.
instance IsCommand Commands where
  parseCommand = hsubparser $
    mconcat [ cmd "init" "Interactive system initialization" (pure InitCommand)
            , cmd "server" "Start the HTTP server" (pure ServerCommand)
            , cmd "info" "Display evaluated config" (pure InfoCommand)
            , cmd "policy" "Edit site policy settings" (PolicyCommand <$> Policy.options)
            , cmd "admin" "Manage admin accounts" (AdminCommand <$> Admin.options)
            ]
    where
      cmd :: String -> String -> Parser a -> Mod CommandFields a
      cmd name desc p = command name (info p (progDesc desc))

--------------------------------------------------------------------------------
newtype Boot a = Boot
  { runBoot :: ExceptT ShellError IO a }
  deriving ( Functor, Applicative, Monad
           , MonadIO, MonadError ShellError
           )

--------------------------------------------------------------------------------
-- | Main entry point.
run :: IO ()
run = do
  -- General process settings:
  void (setFileCreationMask 0o077)

  -- Option parsing and processing:
  options <- enableImplicitOptions <$> parse

  -- Generate the initialization commands:
  (cfg, initcmd) <- runExceptT (runBoot $ boot options) >>= checkOrDie

  -- Initialize the cryptography library:
  keyManager <- fileManager (cfg ^. secrets_path)
  crypto <- initCryptoniteT keyManager

  -- Initialize the encryption keys:
  sec <- runExceptT (runCryptoniteT' crypto
           (initCrypto options cfg keyManager)) >>= checkOrDie

  -- Initialize the database.
  db <- DB.initDatabase (cfg ^. database) Nothing

  let partialEnv eremote =
        Env { _env_config  = cfg
            , _env_db      = db
            , _env_crypto  = crypto
            , _env_secrets = sec
            , _env_remote  = eremote
            , _env_site    = Nothing
            }

  let (io, cmd) = dispatch options partialEnv
  runBootCommand options partialEnv initcmd >>= checkOrDie
  whenJust cmd (runCommand options partialEnv >=> checkOrDie)
  io

  where
    checkOrDie :: Either ShellError a -> IO a
    checkOrDie (Right a) = pure a
    checkOrDie (Left e)  = die (show e)

    boot :: Options Commands -> Boot (Config, Command ())
    boot options = do
      (cfg, cmd) <- runInit options
      return (cfg, cmd)

    dispatch :: Options Commands -> PartialEnv -> (IO (), Maybe (Command ()))
    dispatch options penv =
      case Options.command options of
        InitCommand     -> (initInteractive options penv, Nothing)
        ServerCommand   -> (Server.run options penv, Nothing)
        InfoCommand     -> (pass, Just (Info.run options))
        PolicyCommand o -> (pass, Just (Policy.run o))
        AdminCommand o  -> (pass, Just (Admin.run o))

--------------------------------------------------------------------------------
-- | Some commands imply some of the global options.
enableImplicitOptions :: Options Commands -> Options Commands
enableImplicitOptions input =
  case Options.command input of
    InitCommand     -> input { Options.init = True, Options.migrate = True }
    ServerCommand   -> input
    InfoCommand     -> input
    PolicyCommand _ -> input
    AdminCommand _  -> input
