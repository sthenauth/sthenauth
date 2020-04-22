-- |
--
-- Copyright:
-- This file is part of the package sthenauth. It is subject to the
-- license terms in the LICENSE file found in the top-level directory
-- of this distribution and at:
--
-- git://code.devalot.com/sthenauth.git
--
-- No part of this package, including this file, may be copied,
-- modified, propagated, or distributed except according to the terms
-- contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.Core.Logger
  ( Logger,
    Severity (..),
    newLogger,
    log,
    logInfo,
  )
where

import Data.Aeson ((.=), ToJSON)
import qualified Data.Aeson as Aeson
import qualified System.Log.FastLogger as FastLogger
import qualified System.Mem.Weak as Weak

-- | Logger.
--
-- @since 0.1.0.0
newtype Logger = Logger (FastLogger.TimedFastLogger, Weak.Weak ())

-- | Create a new logger.
--
-- @since 0.1.0.0
newLogger :: IO Logger
newLogger = do
  let logType = FastLogger.LogStdout 4096
  timeCache <- FastLogger.newTimeCache "%Y-%m-%d:%T %z"
  (logger, cleanup) <- FastLogger.newTimedFastLogger timeCache logType
  weak <- Weak.mkWeak logger () (Just cleanup)
  pure $ Logger (logger, weak)

-- | Log severity.
--
-- @since 0.1.0.0
data Severity
  = LogInfo
  | LogHttpReq
  | LogError

instance FastLogger.ToLogStr Severity where
  toLogStr = \case
    LogInfo -> FastLogger.toLogStr (" [INFO] " :: ByteString)
    LogHttpReq -> FastLogger.toLogStr (" [HTTP] " :: ByteString)
    LogError -> FastLogger.toLogStr (" [ERRO] " :: ByteString)

-- | Log a message.
--
-- @since 0.1.0.0
log :: (MonadIO m, ToJSON a) => Logger -> Severity -> a -> m ()
log (Logger (logger, _)) severity msg = liftIO . logger $ \time ->
  mconcat
    [ FastLogger.toLogStr time,
      FastLogger.toLogStr severity,
      FastLogger.toLogStr (Aeson.encode msg),
      FastLogger.toLogStr ("\n" :: ByteString)
    ]

-- | Write some text into the log at 'LogInfo'.
--
-- @since 0.1.0.0
logInfo :: MonadIO m => Text -> Logger -> m ()
logInfo msg logger =
  log logger LogInfo $
    Aeson.object
      [ "message" .= msg
      ]
