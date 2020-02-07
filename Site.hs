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
module Sthenauth.Shell.Site
  ( Actions
  , options
  , run
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Options.Applicative as Options

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Lang.Script (env, envSite)
import Sthenauth.Shell.Command
import Sthenauth.Tables.Site
import Sthenauth.Types

--------------------------------------------------------------------------------
data Actions = Actions
  { setFqdn          :: Maybe Text
  , setAfterLoginUrl :: Maybe Text
  }

--------------------------------------------------------------------------------
options :: Parser Actions
options =
  Actions
    <$> optional (strOption (mconcat
          [ long "set-fqdn"
          , metavar "DOMAIN"
          , help "Set the site's FQDN to DOMAIN"
          ]))

    <*> optional (strOption (mconcat
          [ long "set-after-login"
          , metavar "URL"
          , help "Change the redirection URL after a successful login"
          ]))

--------------------------------------------------------------------------------
run :: Actions -> Command ()
run actions = view (env.envSite) >>= \case
  Nothing ->
    throwing _MissingSiteError ()
  Just site ->
    updateSite (pk site)
      ((siteForUI site)
       { fqdn = fromMaybe (fqdn site) (setFqdn actions)
       , afterLoginUrl = setAfterLoginUrl actions <|> Just (afterLoginUrl site)
       })
