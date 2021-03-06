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
module Sthenauth.API.Middleware
  ( Client,
    ServerMode (..),
    initMiddleware,
    middleware,
  )
where

import Data.List (lookup)
import Data.Time.Clock (getCurrentTime)
import qualified Data.Vault.Lazy as Vault
import qualified Network.HTTP.Types.Header as HTTP
import qualified Network.Wai as Wai
import qualified Network.Wai.Middleware.Throttle as Throttle
import Sthenauth.API.Log
import Sthenauth.Core.Address
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Remote
import Sthenauth.Core.Session (ClearSessionKey (..))
import System.Clock (TimeSpec (..))

-- | Details about a client:
type Client = (Remote, Maybe ClearSessionKey)

-- | A middleware that creates a 'Remote' value and stores it into the
-- request vault.
clientFromRequest :: Vault.Key Client -> Wai.Middleware
clientFromRequest key downstream req res = do
  let headers = Wai.requestHeaders req
  rid <- requestIdFromHeaders headers
  now <- getCurrentTime
  let skey = sessionKeyFromHeaders headers
      r =
        Remote
          { _address = remoteAddr req,
            _userAgent = getUserAgent headers,
            _requestFqdn = hostFQDN headers,
            _requestId = rid,
            _requestTime = now
          }
  let v = Vault.insert key (r, skey) (Wai.vault req)
  downstream (req {Wai.vault = v}) res
  where
    getUserAgent :: HTTP.RequestHeaders -> Text
    getUserAgent = decodeUtf8 . fromMaybe "UNK" . lookup HTTP.hUserAgent
    hostFQDN :: HTTP.RequestHeaders -> Text
    hostFQDN = decodeUtf8 . fromMaybe "localhost" . lookup HTTP.hHost

-- | Extract the remote address from the request.
remoteAddr :: Wai.Request -> Address
remoteAddr req =
  let hs = Wai.requestHeaders req
      fromHeader = lookup "X-Forwarded-For" hs >>= mkAddress . decodeUtf8
   in fromMaybe (fromSockAddr (Wai.remoteHost req)) fromHeader

-- | Middleware that logs the response from downstream.
logResponse :: Logger -> Wai.Middleware
logResponse logger downstream req respond =
  downstream req go
  where
    go :: Wai.Response -> IO Wai.ResponseReceived
    go response = do
      logger_wai logger req (Wai.responseStatus response)
      respond response

data ServerMode
  = -- | Use production settings
    ProductionMode
  | -- | Use test settings.  For example, disable throttling.
    TestMode

data MiddlewareEnv = MiddlewareEnv
  { meThrottle :: Throttle.Throttle Address,
    meVaultKey :: Vault.Key Client,
    meLogger :: Logger
  }

-- | Initialize the middleware layer.
--
-- @since 0.1.0
initMiddleware :: Vault.Key Client -> Logger -> ServerMode -> IO MiddlewareEnv
initMiddleware key logger mode = do
  let settings =
        ( Throttle.defaultThrottleSettings
            (TimeSpec 3600 0)
        )
          { -- 2 requests a second with a small burst:
            Throttle.throttleSettingsRate = 1,
            Throttle.throttleSettingsPeriod = 500_000,
            Throttle.throttleSettingsBurst = 2,
            Throttle.throttleSettingsIsThrottled = modeIsThrottled mode
          }
  MiddlewareEnv
    <$> Throttle.initCustomThrottler settings (Right . remoteAddr)
    <*> pure key
    <*> pure logger
  where
    modeIsThrottled :: ServerMode -> Wai.Request -> Bool
    modeIsThrottled = \case
      ProductionMode -> const True
      TestMode -> const False

-- | All middleware components composed together.
middleware :: MiddlewareEnv -> Wai.Middleware
middleware MiddlewareEnv {..} =
  Throttle.throttle meThrottle
    . clientFromRequest meVaultKey
    . logResponse meLogger
