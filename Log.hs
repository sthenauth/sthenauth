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
module Sthenauth.API.Log
  ( Logger(..)
  , withLogger
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Exception (bracket)
import qualified Data.Aeson as Aeson
import Data.Time.Format (formatTime, defaultTimeLocale)
import qualified Data.UUID as UUID
import Network.HTTP.Types.Status
import Network.Wai
import System.Log.FastLogger

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Various loggers.
data Logger = Logger
  { logger_wai :: Request -> Status -> IO ()
    -- ^ A logger to log WAI requests.

  , logger_error :: forall a . (ToJSON a) => Remote -> a -> IO ()
    -- ^ A general purpose logger.
  }

--------------------------------------------------------------------------------
-- Create a logger and close it when it's not needed any longer.
withLogger :: forall a . (Request -> Maybe Remote) -> (Logger -> IO a) -> IO a
withLogger getRemote f = bracket open snd (go . fst)

  where
    -- Open a logger.
    open :: IO (FastLogger, IO ())
    open = newFastLogger (LogStdout 4096)

    -- What to do with the open logger.
    go :: FastLogger -> IO a
    go fl = f (Logger (forWAI fl) (forGP fl "E"))

    -- How to format time stamps.
    timeFormat :: String
    timeFormat = "%d/%b/%Y:%T %z"

    -- How to log 'Remote' values.
    formatRemote :: Maybe Remote -> LogStr -> LogStr
    formatRemote Nothing  others = "[] - - - " <> others <> " - \n"
    formatRemote (Just r) others = mconcat
      [ " ["
      , toLogStr (formatTime defaultTimeLocale timeFormat (r ^. requestTime))
      , "] "
      , toLogStr (UUID.toASCIIBytes (r ^. requestId))
      , " "
      , toLogStr (encodeAddress (r ^. address))
      , " "
      , toLogStr (r ^. requestFqdn)
      , " "
      , others
      , " "
      , toLogStr (r ^. userAgent)
      , "\n"
      ]

    -- A logger for WAI.
    forWAI :: FastLogger -> Request -> Status -> IO ()
    forWAI fl req status =
      let str = formatRemote (getRemote req) $ mconcat
                  [ "\""
                  , toLogStr (requestMethod req)
                  , " "
                  , toLogStr (rawPathInfo req)
                  , " "
                  , toLogStr (show (httpVersion req) :: Text)
                  , "\" "
                  , toLogStr (show (statusCode status) :: Text)
                  ]
      in fl ("A" <> str)

    -- A general purpose logger:
    forGP :: (ToJSON b) => FastLogger -> LogStr -> Remote -> b -> IO ()
    forGP fl s r x = fl (s <> formatRemote (Just r) (toLogStr $ Aeson.encode x))
