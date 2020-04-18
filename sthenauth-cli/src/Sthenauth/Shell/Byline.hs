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

-}
module Sthenauth.Shell.Byline
  ( LiftByline
  , liftByline

  , LiftBylineC
  , runLiftByline
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Control.Carrier.Error.Either
import Sthenauth.Core.Error
import System.Console.Byline as Byline

--------------------------------------------------------------------------------
data LiftByline m k
  = forall a. LiftByline (Byline IO a) (a -> m k)

deriving instance Functor m => Functor (LiftByline m)

instance HFunctor LiftByline where
  hmap f = \case
    LiftByline b k -> LiftByline b (f . k)

instance Effect LiftByline where
  thread ctx handler = \case
    LiftByline b k -> LiftByline b (handler . (<$ ctx) . k)

--------------------------------------------------------------------------------
-- | Lift a 'Byline' action into an effect.
--
-- @since 0.1.0.0
liftByline :: Has LiftByline sig m => Byline IO a -> m a
liftByline = send . (`LiftByline` pure)

--------------------------------------------------------------------------------
newtype LiftBylineC m a = LiftBylineC
  { runLiftBylineC :: ErrorC Sterr m a
  }
  deriving newtype (Functor, Applicative, Monad, MonadIO)

--------------------------------------------------------------------------------
instance (MonadIO m, Algebra sig m, Effect sig)
  => Algebra (LiftByline :+: sig) (LiftBylineC m) where
    alg = \case
      R other ->
        LiftBylineC (alg (R (handleCoercible other)))

      L (LiftByline b k) ->
        liftIO (Byline.runByline b) >>= \case
          Nothing -> LiftBylineC (throwError (RuntimeError "unexpected termination"))
          Just x  -> k x

--------------------------------------------------------------------------------
-- | Run the 'LiftByline' effect.
--
-- @since 0.1.0.0
runLiftByline :: Has (Throw Sterr) sig m => LiftBylineC m a -> m a
runLiftByline = runLiftBylineC >>> runError >=> either throwError pure
