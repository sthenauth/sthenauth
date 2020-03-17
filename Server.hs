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
  ( main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Data.Vault.Lazy as Vault
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.Wai.Handler.WarpTLS as Warp
import qualified Paths_sthenauth as Sthenauth
import Servant.API
import Servant.Server
import Servant.Server.StaticFiles (serveDirectoryFileServer)
import Sthenauth.API.Handlers
import Sthenauth.API.Log
import Sthenauth.API.Middleware
import Sthenauth.API.Monad
import Sthenauth.API.Routes
import Sthenauth.CertAuth.TLS (serverSettingsForTLS)
import Sthenauth.Core.Runtime

--------------------------------------------------------------------------------
-- | A server for the 'Sthenauth' API.
apiServer :: Runtime -> Client -> Logger -> Server API
apiServer env client logger = hoistServer api (runRequest env client logger) app

--------------------------------------------------------------------------------
-- | A server for the final API.
server :: Runtime -> Vault.Key Client -> Logger -> FilePath -> Server FinalAPI
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
main :: Runtime -> IO ()
main env = do
  path <- Sthenauth.getDataDir
  rkey <- Vault.newKey

  withLogger (fmap fst . Vault.lookup rkey . Wai.vault) $ \logger -> do
    let settings = Warp.defaultSettings & Warp.setPort 3001
        server'  = serve finalapi (server env rkey logger (path </> "www"))
    tls <- serverSettingsForTLS env
    Warp.runTLS tls settings (middleware rkey logger server')
