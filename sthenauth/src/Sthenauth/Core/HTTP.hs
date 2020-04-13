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
  , HttpR
  , initHTTP
  , runHTTP
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Control.Carrier.Reader
import Control.Exception.Safe (try)
import GHC.Generics (Generic1)
import Network.HTTP.Client (Request, Response)
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Client.TLS (newTlsManager)
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
-- | Internal HTTP runtime value.
newtype HttpR = Runtime HTTP.Manager

--------------------------------------------------------------------------------
-- | A carrier for the HTTP effect.
newtype HttpC m a = HttpC
  { runHttpC :: ReaderC HttpR m a }
  deriving newtype (Functor, Applicative, Monad, MonadIO, MonadTrans)

instance (MonadIO m, Has (Throw Sterr) sig m) => Algebra (HTTP :+: sig) (HttpC m) where
  alg = \case
    R other -> HttpC (alg (R (handleCoercible other)))
    L (HTTP req k) -> do
      Runtime mgr <- HttpC ask
      liftIO (try (HTTP.httpLbs req mgr)) >>= \case
        Left e  -> throwError (HttpException e)
        Right r -> k r

--------------------------------------------------------------------------------
-- | Initialize a runtime value for the HTTP effect.
initHTTP :: MonadIO m => m HttpR
initHTTP = Runtime <$> newTlsManager

--------------------------------------------------------------------------------
-- | Discharge the HTTP effect.
runHTTP :: HttpR -> HttpC m a -> m a
runHTTP r = runReader r . runHttpC
