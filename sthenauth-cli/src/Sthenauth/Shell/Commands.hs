-- |
--
-- Copyright:
--   This file is part of the package sthenauth. It is subject to the
--   license terms in the LICENSE file found in the top-level directory
--   of this distribution and at:
--
--     https://code.devalot.com/sthenauth/sthenauth
--
--   No part of this package, including this file, may be copied,
--   modified, propagated, or distributed except according to the terms
--   contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.Shell.Commands
  ( main,
  )
where

-- Imports:
import qualified Control.Carrier.Database as DB
import Control.Monad.Crypto.Cryptonite (KeyManager)
import Data.Time.Clock (getCurrentTime)
import Options.Applicative
import Sthenauth.Core.Address (localhost)
import Sthenauth.Core.Config
import Sthenauth.Core.CurrentUser (isAdmin)
import Sthenauth.Core.Error
import Sthenauth.Core.Logger (Logger)
import Sthenauth.Core.Remote
import Sthenauth.Effect (Sthenauth, getCurrentUser)
import Sthenauth.Effect.Carrier
import qualified Sthenauth.Shell.Admin as Admin
import Sthenauth.Shell.AuthN (authenticate)
import Sthenauth.Shell.Byline
import qualified Sthenauth.Shell.Elm as Elm
import Sthenauth.Shell.IO
import qualified Sthenauth.Shell.Info as Info
import qualified Sthenauth.Shell.Init as Init
import Sthenauth.Shell.Options
import qualified Sthenauth.Shell.Options as Options
import qualified Sthenauth.Shell.Policy as Policy
import qualified Sthenauth.Shell.Provider as Provider
import qualified Sthenauth.Shell.Site as Site
import qualified System.Metrics as Metrics
import System.PosixCompat.Files (setFileCreationMask)

-- | The various commands that can be executed.
data Commands a
  = AdminCommand Admin.Action
  | ElmCommand Elm.Options
  | InfoCommand
  | InitCommand
  | PolicyCommand Policy.Action
  | ProviderCommand Provider.Action
  | SiteCommand Site.Actions
  | AdditionalCommand a

data RunAuthenticatedWith m
  = RunWithoutAuth (IO ())
  | RunAuthenticated (m ())

-- Command line parser for each command.
instance IsCommand alt => IsCommand (Commands alt) where
  parseCommand =
    hsubparser
      ( mconcat
          [ cmd "admin" "Manage admin accounts" (AdminCommand <$> Admin.options),
            cmd "info" "Display evaluated config" (pure InfoCommand),
            cmd "init" "Interactive system initialization" (pure InitCommand),
            cmd "policy" "Edit site policy settings" (PolicyCommand <$> Policy.options),
            cmd "provider" "Manage authentication providers" (ProviderCommand <$> Provider.options),
            cmd "site" "Manage site settings" (SiteCommand <$> Site.options)
          ]
      )
      <|> (AdditionalCommand <$> parseCommand)
      <|> internalCommands
    where
      cmd :: String -> String -> Parser a -> Mod CommandFields a
      cmd name desc p = command name (info p (progDesc desc))
      -- Internal commands that are hidden from the main --help display:
      internalCommands =
        hsubparser $
          mconcat
            [ cmd "elm" "Generate UI Elm files" (ElmCommand <$> Elm.options),
              internal
            ]

type AdditionalCommand a = Environment -> a -> IO ()

-- | Main entry point.
main ::
  forall alt.
  IsCommand alt =>
  Maybe (AdditionalCommand alt) ->
  Maybe DB.Runtime ->
  Maybe KeyManager ->
  Maybe Logger ->
  Maybe Metrics.Store ->
  IO ()
main alt dbruntime keymgr lgr mstore = do
  -- General process settings:
  void (setFileCreationMask 0o077)
  dieOnSigTerm
  -- Option parsing and processing:
  options <- enableImplicitOptions <$> parseOptions
  config <- loadConfig options
  env <- initSthenauth config dbruntime keymgr lgr mstore >>= checkOrDie
  case dispatch options config env of
    RunWithoutAuth k -> shellIO k & runError >>= checkOrDie
    RunAuthenticated k -> do
      rid <- genRequestId
      time <- getCurrentTime
      let remote =
            Remote
              { _address = localhost,
                _userAgent = "Sthenauth Command Line",
                _requestFqdn = optionsSite options,
                _requestId = rid,
                _requestTime = time
              }
      let action = do
            authenticate options
            cu <- getCurrentUser
            if isAdmin cu
              then k
              else throwUserError PermissionDenied
      runSthenauth env remote action
        & runLiftByline
        & runError >>= checkOrDie
  where
    -- Die if we get a 'Left'.
    checkOrDie :: Either Sterr a -> IO a
    checkOrDie (Right a) = pure a
    checkOrDie (Left e) = die (show e)
    -- Dispatch based on command line options.
    dispatch ::
      MonadIO m =>
      Has Sthenauth sig m =>
      Has (Throw Sterr) sig m =>
      Has LiftByline sig m =>
      Options (Commands alt) ->
      Config ->
      Environment ->
      RunAuthenticatedWith m
    dispatch options cfg env =
      case Options.optionsCommand options of
        AdditionalCommand o -> RunWithoutAuth $ maybe (pure ()) (\c -> c env o) alt
        AdminCommand o -> RunAuthenticated (Admin.main o)
        ElmCommand o -> RunWithoutAuth (Elm.main o)
        InfoCommand -> RunAuthenticated (Info.main cfg)
        InitCommand -> RunWithoutAuth (Init.main env options)
        PolicyCommand o -> RunAuthenticated (Policy.main o)
        ProviderCommand o -> RunAuthenticated (Provider.main o)
        SiteCommand o -> RunAuthenticated (Site.main o)

-- | Some commands imply some of the global options.
enableImplicitOptions :: Options (Commands a) -> Options (Commands a)
enableImplicitOptions input =
  case Options.optionsCommand input of
    InitCommand ->
      input
        { Options.optionsInit = True,
          Options.optionsMigrate = True
        }
    _ -> input
