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
  , main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Options.Applicative as Options
import Sthenauth.Core.Site
import Sthenauth.Shell.Command

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
main :: Actions -> Command ()
main actions = do
  site <- asks currentSite
  updateSite (siteId site)
    ((siteForUI site)
      { siteFqdn = fromMaybe (siteFqdn site) (setFqdn actions)
      , afterLoginUrl = setAfterLoginUrl actions <|> Just (afterLoginUrl site)
      })
