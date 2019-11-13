{-# LANGUAGE FlexibleContexts #-}

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
module Sthenauth.API.Server
  ( run
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import qualified Data.Vault.Lazy as Vault
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import Servant.API
import Servant.Server
import Servant.Server.StaticFiles (serveDirectoryFileServer)
import System.FilePath

--------------------------------------------------------------------------------
-- Project Imports:
import qualified Paths_sthenauth as Sthenauth
import Sthenauth.API.Handlers
import Sthenauth.API.Middleware
import Sthenauth.API.Log
import Sthenauth.API.Monad
import qualified Sthenauth.Shell.Command as Command

--------------------------------------------------------------------------------
-- | The final API which includes a file server for the UI files.
type FinalAPI = "auth" :> Vault :> (API :<|> Raw)

--------------------------------------------------------------------------------
-- | The proxy value for the 'Sthenauth' API.
api :: Proxy API
api = Proxy

--------------------------------------------------------------------------------
-- | The proxy value for the final API.
finalapi :: Proxy FinalAPI
finalapi = Proxy

--------------------------------------------------------------------------------
-- | A server for the 'Sthenauth' API.
apiServer :: Command.Env -> Client -> Logger -> Server API
apiServer env client logger = hoistServer api (runRequest env client logger) app

--------------------------------------------------------------------------------
-- | A server for the final API.
server :: Command.Env -> Vault.Key Client -> Logger -> FilePath -> Server FinalAPI
server env key logger path vault =
  case Vault.lookup key vault of
    Nothing     -> error "shouldn't happen"
    Just client -> apiServer env client logger :<|> serveDir path

  where
    serveDir :: FilePath -> ServerT Raw m0
    serveDir = serveDirectoryFileServer
    -- FIXME: Must redirect /auth to /auth/ or <script src=""> won't work!

--------------------------------------------------------------------------------
-- | Run the actual web server.
run :: Command.Env -> IO ()
run e = do
  path <- Sthenauth.getDataDir
  rkey <- Vault.newKey

  withLogger (fmap fst . Vault.lookup rkey . Wai.vault) $ \logger -> do
    let settings = Warp.defaultSettings & Warp.setPort 3001
        server'  = serve finalapi (server e rkey logger (path </> "www"))
    Warp.runSettings settings (middleware rkey logger server')
