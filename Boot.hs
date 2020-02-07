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
import Control.Monad.Crypto.Cryptonite
import qualified Control.Monad.Database as DB
import Options.Applicative
import System.Exit (die)
import System.PosixCompat.Files (setFileCreationMask)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Lang.Script
import Sthenauth.Shell.Command
import Sthenauth.Shell.Error
import Sthenauth.Shell.Init
import Sthenauth.Shell.Options (Options, IsCommand(..), parse)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Types
import Sthenauth.Types.CertAuthT (initCertAuth)

--------------------------------------------------------------------------------
-- Sub-commands:
import qualified Sthenauth.Shell.Admin as Admin
import qualified Sthenauth.Shell.Info as Info
import qualified Sthenauth.Shell.Policy as Policy
import qualified Sthenauth.Shell.Provider as Provider
import qualified Sthenauth.Shell.Server as Server
import qualified Sthenauth.Shell.Site as Site

--------------------------------------------------------------------------------
-- | The various commands that can be executed.
data Commands
  = AdminCommand Admin.Action
  | InfoCommand
  | InitCommand
  | PolicyCommand Policy.SubCommand
  | ProviderCommand Provider.SubCommand
  | ServerCommand
  | SiteCommand Site.Actions

--------------------------------------------------------------------------------
-- Command line parser for each command.
instance IsCommand Commands where
  parseCommand = hsubparser $
    mconcat [ cmd "admin" "Manage admin accounts" (AdminCommand <$> Admin.options)
            , cmd "info" "Display evaluated config" (pure InfoCommand)
            , cmd "init" "Interactive system initialization" (pure InitCommand)
            , cmd "policy" "Edit site policy settings" (PolicyCommand <$> Policy.options)
            , cmd "provider" "Manage authentication providers" (ProviderCommand <$> Provider.options)
            , cmd "server" "Start the HTTP server" (pure ServerCommand)
            , cmd "site" "Manage site settings" (SiteCommand <$> Site.options)
            ]
    where
      cmd :: String -> String -> Parser a -> Mod CommandFields a
      cmd name desc p = command name (info p (progDesc desc))

--------------------------------------------------------------------------------
newtype Boot a = Boot
  { runBoot :: ExceptT ShellError IO a }
  deriving newtype
    ( Functor, Applicative, Monad
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
  keyManager <- fileManager (cfg ^. secretsPath)
  crypto <- initCryptoniteT keyManager

  -- Initialize the encryption keys:
  sec <- runExceptT (runCryptoniteT' crypto
           (initCrypto options cfg keyManager)) >>= checkOrDie

  -- Initialize the database.
  db <- DB.initRuntime (cfg ^. database) Nothing

  let renv = Env
        { _envConfig   = cfg
        , _envDb       = db
        , _envCrypto   = crypto
        , _envSecrets  = sec
        , _envSite     = Nothing
        , _envCertAuth = initCertAuth (cfg ^. certAuth) crypto db
        }

  let (io, cmd) = dispatch options renv
  runBootCommand options renv initcmd >>= checkOrDie
  whenJust cmd (runCommand options renv >=> checkOrDie)
  io

  where
    checkOrDie :: Either ShellError a -> IO a
    checkOrDie (Right a) = pure a
    checkOrDie (Left e)  = die (show e)

    boot :: Options Commands -> Boot (Config, Command ())
    boot options = do
      (cfg, cmd) <- runInit options
      return (cfg, cmd)

    dispatch :: Options Commands -> Env -> (IO (), Maybe (Command ()))
    dispatch options renv =
      case Options.command options of
        AdminCommand o    -> (pass, Just (Admin.run o))
        InfoCommand       -> (pass, Just (Info.run options))
        InitCommand       -> (initInteractive options renv, Nothing)
        PolicyCommand o   -> (pass, Just (Policy.run o))
        ProviderCommand o -> (pass, Just (Provider.run o))
        ServerCommand     -> (Server.run options renv, Nothing)
        SiteCommand o     -> (pass, Just (Site.run o))

--------------------------------------------------------------------------------
-- | Some commands imply some of the global options.
enableImplicitOptions :: Options Commands -> Options Commands
enableImplicitOptions input =
  case Options.command input of
    AdminCommand _    -> input
    InfoCommand       -> input
    InitCommand       -> input { Options.init = True, Options.migrate = True }
    PolicyCommand _   -> input
    ProviderCommand _ -> input
    ServerCommand     -> input
    SiteCommand _     -> input
