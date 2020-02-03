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
module Sthenauth.API.Middleware
  ( Client
  , middleware
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.List (lookup)
import Data.Time.Clock (getCurrentTime)
import qualified Data.Vault.Lazy as Vault
import qualified Network.HTTP.Types.Header as HTTP
import qualified Network.Socket as Net
import qualified Network.Wai as Wai

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.API.Log
import Sthenauth.Tables.Session (ClearSessionKey(..))
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Details about a client:
type Client = (Remote , Maybe ClearSessionKey)

--------------------------------------------------------------------------------
-- | A middleware that creates a 'Remote' value and stores it into the
-- request vault.
clientFromRequest :: Vault.Key Client -> Wai.Middleware
clientFromRequest key downstream req res = do
  let headers = Wai.requestHeaders req

  rid <- requestIdFromHeaders headers
  now <- getCurrentTime

  let skey = sessionKeyFromHeaders headers
      r = Remote { _address     = remoteAddr headers (Wai.remoteHost req)
                 , _userAgent   = getUserAgent headers
                 , _requestFqdn = hostFQDN headers
                 , _requestId   = rid
                 , _requestTime = now
                 }

  let v = Vault.insert key (r, skey) (Wai.vault req)
  downstream (req {Wai.vault = v}) res

  where
    getUserAgent :: HTTP.RequestHeaders -> Text
    getUserAgent = decodeUtf8 . fromMaybe "UNK" . lookup HTTP.hUserAgent

    hostFQDN :: HTTP.RequestHeaders -> Text
    hostFQDN = decodeUtf8 . fromMaybe "localhost" . lookup HTTP.hHost

    remoteAddr :: HTTP.RequestHeaders -> Net.SockAddr -> Address
    remoteAddr hs sa =
      let fromHeader = lookup "X-Forwarded-For" hs >>= mkAddress . decodeUtf8
      in fromMaybe (fromSockAddr sa) fromHeader

--------------------------------------------------------------------------------
-- | Middleware that logs the response from downstream.
logResponse :: Logger -> Wai.Middleware
logResponse logger downstream req respond =
    downstream req go

  where
    go :: Wai.Response -> IO Wai.ResponseReceived
    go response = do
      logger_wai logger req (Wai.responseStatus response)
      respond response

--------------------------------------------------------------------------------
-- | All middleware components composed together.
middleware :: Vault.Key Client -> Logger -> Wai.Middleware
middleware k l = clientFromRequest k . logResponse l
