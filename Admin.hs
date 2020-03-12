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
  , main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Iolaus.Database.Query (Query)
import Options.Applicative as Options
import Sthenauth.Core.Account as Account
import Sthenauth.Core.Admin
import Sthenauth.Core.Error
import Sthenauth.Core.Site (siteId)
import Sthenauth.Database.Effect
import Sthenauth.Core.Action (liftByline)
import Sthenauth.Providers.Local.LocalAccount
import Sthenauth.Providers.Local.Login
import Sthenauth.Shell.Command
import System.Console.Byline as Byline

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
-- | FIXME: centralize this code and fire events!
main :: Action -> Command ()
main = \case
    Promote t -> go (t >>= toLogin) (alterAdmin . PromoteToAdmin)
    Demote  t -> go (t >>= toLogin) (alterAdmin . DemoteFromAdmin)
  where
    go :: Maybe Login -> (AccountId -> Query ()) -> Command ()
    go Nothing f = do
      login <- liftByline (Byline.ask "Username/Email to alter: " Nothing)
      go (toLogin login) f
    go (Just login) f = do
      site <- asks currentSite
      getAccountFromLogin (siteId site) login >>= \case
        Nothing -> throwUserError InvalidUsernameOrEmailError
        Just acct -> runQuery (f (accountId acct))
