{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    git://code.devalot.com/sthenauth.git

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

Information about a remote connection (browser, tool, etc.)

-}
module Sthenauth.Core.Remote
  ( Remote(..)
  , RequestTime
  , address
  , userAgent
  , requestFqdn
  , requestId
  , requestTime
  , genRequestId
  , requestIdFromHeaders
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeLenses)
import Data.List (lookup)
import Data.Time.Clock (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Iolaus.Database.JSON (liftJSON)
import qualified Network.HTTP.Types.Header as HTTP
import Sthenauth.Core.Address (Address)
import System.Random (randomIO)

--------------------------------------------------------------------------------
type RequestTime = UTCTime

--------------------------------------------------------------------------------
-- | Details about a remote user.
data Remote = Remote
  { _address :: Address
    -- ^ IP address of remote user.

  , _userAgent :: Text
    -- ^ The User-Agent string.

  , _requestFqdn :: Text
    -- ^ The domain name from the request.

  , _requestId :: UUID
    -- ^ Optional request ID.

  , _requestTime :: UTCTime
    -- ^ The time the request was initiated.

  }
  deriving (Generic, Show, Eq)
  deriving (ToJSON, FromJSON) via GenericJSON Remote

makeLenses ''Remote
liftJSON ''Remote

--------------------------------------------------------------------------------
-- | Generate a fresh, random request ID.
genRequestId :: (MonadIO m) => m UUID
genRequestId = liftIO randomIO

--------------------------------------------------------------------------------
-- | Parse a request ID HTTP header.  If that fails generate a new
-- request ID.
requestIdFromHeaders :: (MonadIO m) => HTTP.RequestHeaders -> m UUID
requestIdFromHeaders hs =
  case lookup "X-Request-Id" hs of
    Nothing -> genRequestId
    Just bs -> maybe genRequestId pure (UUID.fromASCIIBytes bs)
