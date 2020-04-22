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
module Sthenauth.API.Log
  ( Logger (..),
    withLogger,
  )
where

import Control.Lens ((^.))
import Data.Aeson ((.=), ToJSON)
import qualified Data.Aeson as Aeson
import Network.HTTP.Types.Status
import Network.Wai
import Sthenauth.Core.Address (encodeAddress)
import Sthenauth.Core.Logger (Severity (..), log)
import Sthenauth.Core.Remote
import Sthenauth.Effect.Runtime (Environment, logger)

-- | Various loggers.
data Logger = Logger
  { -- | A logger to log WAI requests.
    logger_wai :: Request -> Status -> IO (),
    -- | A general purpose logger.
    logger_error :: forall a. (ToJSON a) => Remote -> a -> IO ()
  }

-- | Create a logger and close it when it's not needed any longer.
withLogger ::
  Environment ->
  (Request -> Maybe Remote) ->
  (Logger -> IO a) ->
  IO a
withLogger env getRemote f =
  f $
    Logger
      { logger_wai = forWAI,
        logger_error = forGP
      }
  where
    formatRemote :: Maybe Remote -> [(Text, Aeson.Value)]
    formatRemote = \case
      Nothing -> mempty
      Just remote ->
        [ "request_id" .= (remote ^. requestId),
          "remote_address" .= encodeAddress (remote ^. address),
          "request_host" .= (remote ^. requestFqdn),
          "user_agent" .= (remote ^. userAgent)
        ]
    -- A logger for WAI requests.
    forWAI :: Request -> Status -> IO ()
    forWAI req status = do
      let msg =
            Aeson.object $
              formatRemote (getRemote req)
                ++ [ "request_method" .= (decodeUtf8 (requestMethod req) :: Text),
                     "request_path" .= (decodeUtf8 (rawPathInfo req) :: Text),
                     "http_version" .= (show (httpVersion req) :: Text),
                     "http_status" .= (show (statusCode status) :: Text)
                   ]
      log (env ^. logger) LogHttpReq msg
    -- A general purpose logger:
    forGP :: (ToJSON a) => Remote -> a -> IO ()
    forGP remote msg = do
      let val = Aeson.object $ formatRemote (Just remote) ++ ["error" .= msg]
      log (env ^. logger) LogError val
