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
module Sthenauth.Shell.Admin
  ( Action
  , options
  , run
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Options.Applicative as Options

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command
import Sthenauth.Shell.Options (Options)
import Sthenauth.Shell.Helpers

--------------------------------------------------------------------------------
data CreateOpts = CreateOpts
  { coEmailAddr :: Maybe Text
  , coPassword  :: Maybe Text
  }

--------------------------------------------------------------------------------
newtype Action
  = Create CreateOpts

--------------------------------------------------------------------------------
options :: Options.Parser Action
options = Options.hsubparser $ mconcat
    [ cmd "create" "Create a new admin account" createOpts
    ]
  where
    cmd :: String -> String -> Parser a -> Mod CommandFields a
    cmd name desc p = command name (info p (progDesc desc))

    createOpts :: Options.Parser Action
    createOpts = fmap Create $ CreateOpts
      <$> optional (option str $ mconcat
            [ short 'e'
            , long "email"
            , metavar "ADDR"
            , help "Account email address"
            ])

      <*> optional (option str $ mconcat
            [ short 'p'
            , long "password"
            , metavar "STR"
            , help "Initial account password"
            ])

--------------------------------------------------------------------------------
runCreate :: CreateOpts -> Command ()
runCreate opts = do
  email <- maybeAskEmail (coEmailAddr opts)
  undefined

--------------------------------------------------------------------------------
run :: Action -> Command ()
run = \case
  Create opts -> runCreate opts
