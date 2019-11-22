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
import System.Console.Byline as Byline

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command
import Sthenauth.Lang.Sthenauth
import Sthenauth.Scripts.Admin
import Sthenauth.Tables.Account as Account

--------------------------------------------------------------------------------
-- | Sub-commands and options.
data Action
  = Promote (Maybe Text)
  | Demote  (Maybe Text)

--------------------------------------------------------------------------------
options :: Options.Parser Action
options = Options.hsubparser $ mconcat
    [ cmd "promote" "Promote an account to an admin" promoteOpts
    , cmd "demote"  "Remove admin status on an account" demoteOpts
    ]
  where
    cmd :: String -> String -> Parser a -> Mod CommandFields a
    cmd name desc p = command name (info p (progDesc desc))

    promoteOpts :: Parser Action
    promoteOpts = Promote <$> optional (option str login)

    demoteOpts :: Parser Action
    demoteOpts = Demote <$> optional (option str login)

    login = mconcat
      [ long "login"
      , short 'l'
      , metavar "STR"
      , help "Account username or email address"
      ]

--------------------------------------------------------------------------------
run :: Action -> Command ()
run act =
  case act of
    Promote t -> go t promoteToAdmin
    Demote  t -> go t demoteFromAdmin

  where
    go :: Maybe Text -> (AccountId -> Sthenauth ()) -> Command ()
    go mt f =
      let go' t = liftSthenauth (withAccount t $ \a -> f (Account.pk a))
      in case mt of
        Just t  ->
          go' t
        Nothing ->
          liftByline (Byline.ask "Username/Email to alter: " Nothing) >>= go'
