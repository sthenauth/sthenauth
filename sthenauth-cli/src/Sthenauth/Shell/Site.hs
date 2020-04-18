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
import Sthenauth.Core.Error
import Sthenauth.Core.Site
import Sthenauth.Core.URL
import Sthenauth.Effect

--------------------------------------------------------------------------------
data Actions = Actions
  { setFqdn          :: Maybe Text
  , setAfterLoginUrl :: Maybe URL
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

    <*> optional (option (maybeReader strToURL) (mconcat
          [ long "set-after-login"
          , metavar "URL"
          , help "Change the redirection URL after a successful login"
          ]))

--------------------------------------------------------------------------------
main
  :: Has Sthenauth sig m
  => Has (Throw Sterr) sig m
  => Actions
  -> m ()
main Actions{..} =
  modifySite $ \s ->
    s { siteFqdn = fromMaybe (siteFqdn s) setFqdn
      , siteAfterLoginUrl = fromMaybe (siteAfterLoginUrl s) setAfterLoginUrl
      }
