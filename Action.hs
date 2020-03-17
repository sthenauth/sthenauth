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
module Sthenauth.Core.Action
  ( Action
  , ActionEff
  , Env(..)
  , dischargeMonadRandom
  , runAction

  , MonadByline
  , liftByline
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Control.Carrier.Database (Database, DatabaseC, runDatabase)
import Control.Carrier.Error.Either hiding (Error)
import Control.Carrier.Lift
import Control.Carrier.Reader
import Control.Carrier.State.Strict
import Crypto.Random (MonadRandom(..))
import Sthenauth.Core.Config (Config)
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Error
import Sthenauth.Core.HTTP
import Sthenauth.Core.Remote
import Sthenauth.Core.Runtime
import Sthenauth.Core.Site (Site)
import Sthenauth.Crypto.Carrier (Crypto, CryptoC, runCrypto, randomByteArray)
import System.Console.Byline (Byline, runByline)

--------------------------------------------------------------------------------
data Env = Env
  { runtime       :: Runtime
  , currentSite   :: Site
  , currentRemote :: Remote
  , currentConfig :: Config
  }

--------------------------------------------------------------------------------
-- | A transformer stack that can run 'Sthenauth' actions.
newtype Action m a = Action
  { unAction ::
      ReaderC Env
        (StateC CurrentUser
          (DatabaseC
            (CryptoC
              (HttpC
                (ErrorC BaseError
                  (LiftC m)))))) a
  }
  deriving newtype (Functor, Applicative, Monad)

type ActionEff m
  =   Reader Env
  :+: State CurrentUser
  :+: Database
  :+: Crypto
  :+: HTTP
  :+: Error
  :+: Lift m

instance MonadIO m => Algebra (ActionEff m) (Action m) where
  alg = Action . alg . handleCoercible

instance MonadTrans Action where
  lift = Action . lift . lift . lift . lift . lift . lift . lift

-- FIXME: Temp hack,
class (Monad m) => MonadByline m where
  liftByline :: Byline IO a -> m a

instance MonadIO m => MonadByline (Action m) where
  liftByline b = Action $
    liftIO (runByline b) >>= \case
      Nothing -> throwError (RuntimeError "unexpected termination")
      Just x  -> return x

--------------------------------------------------------------------------------
newtype ActionM a = ActionM (Action IO a)
  deriving newtype (Functor, Applicative, Monad)

instance Algebra (ActionEff IO) ActionM where
  alg = ActionM . Action . alg . handleCoercible

instance MonadRandom ActionM where
  getRandomBytes = randomByteArray

--------------------------------------------------------------------------------
-- | This is a complete hack to work around orphan instances from the
-- JOSE package.
dischargeMonadRandom :: MonadIO m => ActionM a -> Action m a
dischargeMonadRandom (ActionM k) = do
  env <- ask
  user <- get
  r <- Action . liftIO $
    runAction (runtime env) (currentSite env) (currentRemote env) user k
  case r of
    Left e -> throwError e
    Right (u, a) -> put u $> a

--------------------------------------------------------------------------------
-- | Execute a action inside 'MonadIO'.
runAction
  :: MonadIO m
  => Runtime
  -> Site
  -> Remote
  -> CurrentUser
  -> Action m a
  -> m (Either BaseError (CurrentUser, a))
runAction env site remote user script
  = unAction script
  & runReader (Env env site remote (rtConfig env))
  & runState user
  & runDatabase (rtDb env)
  & runCrypto (rtCrypto env)
  & runHTTP
  & runError
  & runM
