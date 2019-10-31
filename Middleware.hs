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
  ( middleware
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
import Sthenauth.Types
import Sthenauth.Tables.Util (getKey)

--------------------------------------------------------------------------------
-- | A middleware that creates a 'Remote' value and stores it into the
-- request vault.
remoteFromRequest :: Vault.Key Remote -> Wai.Middleware
remoteFromRequest rkey downstream req res = do
  let headers = Wai.requestHeaders req

  rid <- requestIdFromHeaders headers
  now <- getCurrentTime

  let r = Remote { address = remoteAddr headers (Wai.remoteHost req)
                 , user_agent = userAgent headers
                 , request_fqdn = hostFQDN headers
                 , request_id = rid
                 , request_time = now
                 , session_id = getKey <$> sessionIdFromHeaders headers
                 }

  let v = Vault.insert rkey r (Wai.vault req)
  downstream (req {Wai.vault = v}) res

  where
    userAgent :: HTTP.RequestHeaders -> Text
    userAgent = decodeUtf8 . fromMaybe "UNK" . lookup HTTP.hUserAgent

    hostFQDN :: HTTP.RequestHeaders -> Text
    hostFQDN = decodeUtf8 . fromMaybe "localhost" . lookup HTTP.hHost

    remoteAddr :: HTTP.RequestHeaders -> Net.SockAddr -> Address
    remoteAddr hs sa =
      let fromHeader = lookup "X-Forwarded-For" hs >>= mkAddress . decodeUtf8
      in fromMaybe (fromSockAddr sa) fromHeader

--------------------------------------------------------------------------------
-- | All middleware components composed together.
middleware :: Vault.Key Remote -> Wai.Middleware
middleware = remoteFromRequest
