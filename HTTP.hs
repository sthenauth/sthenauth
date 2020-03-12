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

HTTPS client as an effect.

-}
module Sthenauth.Core.HTTP
  ( Client
  , HTTP
  , http

  , HttpC
  , runHTTP
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Network.HTTP.Client.TLS (newTlsManager)

import Control.Algebra
import Control.Carrier.Reader
import Control.Exception.Safe (try)
import Network.HTTP.Client (Request, Response)
import qualified Network.HTTP.Client as HTTP
import Sthenauth.Core.Error

-------------------------------------------------------------------------------
-- | A function that can make simple HTTPS requests.
type Client m = Request -> m (Response LByteString)

--------------------------------------------------------------------------------
-- | An HTTP effect.
data HTTP m k
  = HTTP Request (Response LByteString -> m k)

  deriving stock (Generic1, Functor)
  deriving anyclass (HFunctor, Effect)

--------------------------------------------------------------------------------
-- | Run a simple 'Client' request.
http :: Has HTTP sig m => Client m
http = send . (`HTTP` pure)

--------------------------------------------------------------------------------
-- | A carrier for the HTTP effect.
newtype HttpC m a = HttpC
  { runHttpC :: ReaderC HTTP.Manager m a }
  deriving newtype (Functor, Applicative, Monad, MonadIO, MonadTrans)

instance (MonadIO m, Has Error sig m) => Algebra (HTTP :+: sig) (HttpC m) where
  alg = \case
    R other -> HttpC (alg (R (handleCoercible other)))
    L (HTTP req k) -> do
      mgr <- HttpC ask
      liftIO (try (HTTP.httpLbs req mgr)) >>= \case
        Left e  -> throwError (HttpException e)
        Right r -> k r

--------------------------------------------------------------------------------
-- | Discharge the HTTP effect.
runHTTP :: MonadIO m => HttpC m a -> m a
runHTTP h = do
  mgr <- newTlsManager
  runReader mgr (runHttpC h)
