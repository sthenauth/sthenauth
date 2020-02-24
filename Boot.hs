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
  ( main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Carrier.Error.Either hiding (Error)
import Control.Carrier.Lift
import Control.Monad.Crypto.Cryptonite (fileManager)
import qualified Control.Monad.Database as DB
import Options.Applicative
import Sthenauth.CertAuth.Carrier (initCertAuth)
import Sthenauth.Core.Config
import Sthenauth.Core.Error
import Sthenauth.Core.Runtime
import Sthenauth.Crypto.Carrier (getCryptonite)
import Sthenauth.Shell.Command
import Sthenauth.Shell.Init
import Sthenauth.Shell.Options (Options, IsCommand(..), parse)
import qualified Sthenauth.Shell.Options as Options
import System.Exit (die)
import System.PosixCompat.Files (setFileCreationMask)

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
data RunCommandWith
  = RunIO (IO ())
  | RunCommand (Command ())

--------------------------------------------------------------------------------
-- Command line parser for each command.
instance IsCommand Commands where
  parseCommand = hsubparser $ mconcat
    [ cmd "admin" "Manage admin accounts" (AdminCommand <$> Admin.options)
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
-- | Main entry point.
main :: IO ()
main = do
  -- General process settings:
  void (setFileCreationMask 0o077)

  -- Option parsing and processing:
  options <- enableImplicitOptions <$> parse

  -- Generate the initialization commands:
  (cfg, initcmd) <-
    runInit options
    & runError
    & runM
    & (>>= checkOrDie)

  -- Initialize the cryptography library:
  keyManager <- fileManager (cfg ^. secretsPath)
  crypto <-
    initCrypto options cfg keyManager
    & runError
    & runM
    & (>>= checkOrDie)

  -- Initialize the database.
  db <- DB.initRuntime (cfg ^. database) Nothing

  let renv = Runtime
        { rtConfig   = cfg
        , rtDb       = db
        , rtCrypto   = crypto
        , rtCertAuth = initCertAuth (cfg ^. certAuth) (getCryptonite crypto)
        }

  -- Now that we have a fully constructed environment, run the
  -- post-initialization step.
  initcmd renv
    & runError
    & runM
    & (>>= checkOrDie)

  case dispatch options renv of
    RunIO k      -> k
    RunCommand k -> runCommand options renv k >>= checkOrDie

  where
    checkOrDie :: Either BaseError a -> IO a
    checkOrDie (Right a) = pure a
    checkOrDie (Left e)  = die (show e)

    dispatch :: Options Commands -> Runtime -> RunCommandWith
    dispatch options renv =
      case Options.command options of
        AdminCommand o    -> RunCommand (Admin.main o)
        InfoCommand       -> RunCommand (Info.main options)
        InitCommand       -> RunIO (initInteractive options renv)
        PolicyCommand o   -> RunCommand (Policy.main o)
        ProviderCommand o -> RunCommand (Provider.main o)
        ServerCommand     -> RunIO (Server.main options renv)
        SiteCommand o     -> RunCommand (Site.main o)

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
