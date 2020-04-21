-- |
--
-- Copyright:
--   This file is part of the package sthenauth. It is subject to the
--   license terms in the LICENSE file found in the top-level directory
--   of this distribution and at:
--
--     git://code.devalot.com/sthenauth.git
--
--   No part of this package, including this file, may be copied,
--   modified, propagated, or distributed except according to the terms
--   contained in the LICENSE file.
--
-- License: Apache-2.0
module Main
  ( main,
  )
where

import Control.Exception (throwIO)
import Control.Lens ((.~), (^.))
import qualified Data.Vault.Lazy as Vault
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.Wai.Handler.WarpTLS as Warp
import qualified Options.Applicative as OA
import Paths_sthenauth_daemon (getDataDir)
import Servant.API
import Servant.Server
import Servant.Server.StaticFiles (serveDirectoryFileServer)
import Sthenauth.API.Log (Logger, withLogger)
import Sthenauth.API.Middleware (Client, middleware)
import Sthenauth.API.Routes (API, TopPath)
import Sthenauth.API.Server (apiServer)
import Sthenauth.CertAuth.Carrier
import qualified Sthenauth.CertAuth.Config as CertAuth
import Sthenauth.CertAuth.TLS (serverSettingsForTLS)
import qualified Sthenauth.Core.Config as SA
import qualified Sthenauth.Core.Crypto as SA
import Sthenauth.Core.Error (Sterr)
import Sthenauth.Effect.Runtime (Environment)
import qualified Sthenauth.Effect.Runtime as RT
import qualified Sthenauth.Shell.Commands as Commands
import qualified Sthenauth.Shell.Options as Options
import System.FilePath ((</>))
import qualified System.Metrics as Metrics

-- | The final API which includes a file server for the UI files.
type FinalAPI = TopPath :> Vault :> (API :<|> Raw)

-- | Server options.
data Config = Config
  { -- | The port to listen on.
    configPort :: Int,
    -- | Path to the @www@ directory to serve files out of.
    configWwwDir :: Maybe FilePath
  }

instance Options.IsCommand Config where
  parseCommand =
    OA.hsubparser $
      mconcat
        [ OA.command "server" (OA.info parser (OA.progDesc "API server"))
        ]
    where
      parser =
        Config
          <$> OA.option
            OA.auto
            ( mconcat
                [ OA.long "port",
                  OA.short 'p',
                  OA.metavar "NUM",
                  OA.help "Listen for TLS requests on port NUM",
                  OA.value 43433,
                  OA.showDefault
                ]
            )
          <*> optional
            ( OA.strOption
                ( mconcat
                    [ OA.long "www",
                      OA.short 'w',
                      OA.metavar "DIR",
                      OA.help "Serve files from DIR instead of the default"
                    ]
                )
            )

-- | Called when the command-line sub-command is @server@.
startServer :: Environment -> Config -> IO ()
startServer env cfg = do
  let caConfig =
        CertAuth.defaultCertAuthConfig
          & CertAuth.allowDatabaseMigration
            .~ (env ^. RT.config . SA.runDatabaseMigrations)
  certauthEither <-
    initCertAuth
      caConfig
      (SA.getCryptonite (env ^. RT.crypto))
      (env ^. RT.database)
      & runError
  case certauthEither of
    Left (e :: Sterr) -> throwIO e
    Right ca -> apiServerThread cfg env ca

-- | Run the actual web server.
apiServerThread :: Config -> Environment -> CertAuthEnv -> IO ()
apiServerThread Config {..} env certauth = do
  www <- getDataDir <&> (</> "www")
  rkey <- Vault.newKey
  withLogger (fmap fst . Vault.lookup rkey . Wai.vault) $ \logger -> do
    let settings = Warp.defaultSettings & Warp.setPort configPort
        files = fromMaybe www configWwwDir
        server' = serve finalapi (server rkey logger files)
    tls <- serverSettingsForTLS certauth
    Warp.runTLS tls settings (middleware rkey logger server')
  where
    -- FIXME: Must redirect /auth to /auth/ or <script src=""> won't work!
    server :: Vault.Key Client -> Logger -> FilePath -> Server FinalAPI
    server key logger path vault =
      case Vault.lookup key vault of
        Nothing -> error "shouldn't happen"
        Just client ->
          apiServer env client logger
            :<|> serveDirectoryFileServer path
    finalapi :: Proxy FinalAPI
    finalapi = Proxy

-- | Main entry point.
main :: IO ()
main = do
  store <- Metrics.newStore
  Commands.main (Just startServer) Nothing Nothing (Just store)
