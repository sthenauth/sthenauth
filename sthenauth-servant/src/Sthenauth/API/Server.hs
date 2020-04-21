-- |
--
-- Copyright:
--   This file is part of the package sthenauth. It is subject to the
--   license terms in the LICENSE file found in the top-level directory
--   of this distribution and at:
--
--     https://code.devalot.com/sthenauth/sthenauth
--
--   No part of this package, including this file, may be copied,
--   modified, propagated, or distributed except according to the terms
--   contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.API.Server
  ( apiServer,
  )
where

-- Imports:
import Servant.Server (Server, hoistServer)
import Sthenauth.API.Handlers (app)
import Sthenauth.API.Log (Logger)
import Sthenauth.API.Middleware (Client)
import Sthenauth.API.Monad (runRequest)
import Sthenauth.API.Routes (API, api)
import Sthenauth.Effect.Carrier (Environment)

-- | A server for the 'Sthenauth' API.
apiServer :: Environment -> Client -> Logger -> Server API
apiServer env client logger = hoistServer api (runRequest env client logger) app
