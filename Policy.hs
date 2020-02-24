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
module Sthenauth.Shell.Policy
  ( SubCommand
  , options
  , main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Options.Applicative as Options
import Sthenauth.Core.Policy
import Sthenauth.Lang.Class
import Sthenauth.Lang.Sthenauth
import Sthenauth.Shell.Command

--------------------------------------------------------------------------------
newtype SubCommand
  = ChangeAccountCreationTo AccountCreation

--------------------------------------------------------------------------------
options :: Options.Parser SubCommand
options = Options.hsubparser $ mconcat
    [ cmd "mode" "Change account creation mode" modeOpts
    ]
  where
    cmd :: String -> String -> Parser a -> Mod CommandFields a
    cmd name desc p = command name (info p (progDesc desc))

    modeOpts :: Parser SubCommand
    modeOpts = ChangeAccountCreationTo <$>
      (   flag' AdminInvitation (
            mconcat [ long "admin-invite"
                    , help "Must be invited from an admin"
                    ])
      <|> flag' SelfService (
            mconcat [ long "self-service"
                    , help "Users can create their own accounts"
                    ])
      <|> flag' OnlyFromOIDC (
          mconcat [ long "oidc-only"
                  , help "Users must use a remote OpenID Connect provider"
                  ])
      )

--------------------------------------------------------------------------------
main :: SubCommand -> Command ()
main sub = liftSthenauth $
  case sub of
    ChangeAccountCreationTo mode -> modifyPolicy (accountCreation .~ mode)
