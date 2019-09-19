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
import Control.Monad.Except (runExceptT)
import Options.Applicative
import System.Exit (die)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command (Command, runCommand)
import Sthenauth.Shell.Error
import qualified Sthenauth.Shell.Info as Info
import Sthenauth.Shell.Init
import Sthenauth.Shell.Options (Options, IsCommand(..), parse)
import qualified Sthenauth.Shell.Options as Options
import Sthenauth.Types.Config (Config)

--------------------------------------------------------------------------------
-- | The various commands that can be executed.
data Commands
  = InfoCommand

--------------------------------------------------------------------------------
-- Command line parser for each command.
instance IsCommand Commands where
  parseCommand = hsubparser $
    mconcat [ cmd "info" "Display evaluated config" (pure InfoCommand)
            ]
    where
      cmd :: String -> String -> Parser a -> Mod CommandFields a
      cmd name desc p = command name (info p (progDesc desc))

--------------------------------------------------------------------------------
-- | Main entry point.
run :: IO ()
run = do
  options <- parse :: IO (Options Commands)
  (cfg, cmd) <- runExceptT (runInit options) >>= checkOrDie

  case Options.command options of
    InfoCommand -> runCommandIO cfg (cmd >> Info.run options)

  where
    checkOrDie :: Either ShellError a -> IO a
    checkOrDie (Right a) = pure a
    checkOrDie (Left e)  = die (show e)

    runCommandIO :: Config -> Command a -> IO a
    runCommandIO cfg cmd = runCommand cfg cmd >>= checkOrDie
