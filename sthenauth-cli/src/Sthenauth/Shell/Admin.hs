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
import Options.Applicative as Options
import Sthenauth.Core.Admin
import Sthenauth.Core.Error
import Sthenauth.Effect
import Sthenauth.Shell.Byline

--------------------------------------------------------------------------------
-- | Sub-commands and options.
data Action
  = Promote Login
  | Demote  Login

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
    promoteOpts = Promote <$> option loginReader login

    demoteOpts :: Parser Action
    demoteOpts = Demote <$> option loginReader login

    loginReader = maybeReader (toText >>> toLogin)

    login = mconcat
      [ long "login"
      , short 'l'
      , metavar "STR"
      , help "Account username or email address"
      ]

--------------------------------------------------------------------------------
main
  :: ( Has LiftByline    sig m
     , Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => Action
  -> m ()
main = \case
  Promote login -> alterAccountAdminStatus login PromoteToAdmin
  Demote  login -> alterAccountAdminStatus login DemoteFromAdmin
