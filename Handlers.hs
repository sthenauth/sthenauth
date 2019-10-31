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
module Sthenauth.API.Handlers
  ( API
  , app
  ) where


--------------------------------------------------------------------------------
-- Library Imports:
import Servant.API
import Servant.Server

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Lang.Sthenauth (Sthenauth)
import Sthenauth.Scripts
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Servant API type.
type API = "keys" :> Get '[JSON] JWKSet

--------------------------------------------------------------------------------
-- | Handlers for the @API@ type, running in the 'Sthenauth' monad.
app :: ServerT API Sthenauth
app = activeSiteKeys
