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
module Sthenauth.Effect.Carrier
  ( SthenauthC
  , Runtime
  , initSthenauth
  , createInitialAdminAccount
  , runSthenauth
  ) where

--------------------------------------------------------------------------------
import Control.Algebra
import Control.Carrier.Database (DatabaseC, runDatabase)
import Control.Carrier.Error.Either
import Control.Carrier.Lift
import Control.Carrier.Reader
import Control.Carrier.State.Strict
import Control.Lens ((^.))
import qualified Control.Monad.Crypto.Cryptonite as Crypto
import Crypto.Random (MonadRandom(..))
import Data.Time.Clock (getCurrentTime)
import qualified Iolaus.Database.Query as Query
import Sthenauth.Core.Account (AccountId, accountId)
import qualified Sthenauth.Core.Admin as Admin
import qualified Sthenauth.Core.AuthN as Auth
import Sthenauth.Core.Crypto (CryptoC, runCrypto)
import qualified Sthenauth.Core.Crypto as Crypto
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Database (transaction, runQuery)
import Sthenauth.Core.Error
import Sthenauth.Core.HTTP
import Sthenauth.Core.Policy (sessionCookieName)
import Sthenauth.Core.Remote (Remote)
import Sthenauth.Core.Session (resetSessionCookie)
import Sthenauth.Effect.Algebra
import Sthenauth.Effect.Boot
import Sthenauth.Effect.Runtime
import Sthenauth.Providers.Local.Provider (Credentials(..), insertLocalAccountQuery)
import qualified Sthenauth.Providers.OIDC.Provider as OIDC
import Web.Cookie (SetCookie)

--------------------------------------------------------------------------------
newtype SthenauthC m a = SthenauthC
  { runSthenauthC :: ReaderC Runtime m a
  }
  deriving newtype (Functor, Applicative, Monad, MonadIO)

instance (MonadIO m, Algebra sig m) => Algebra (Sthenauth :+: sig) (SthenauthC m) where
  alg = \case
    R other ->
      SthenauthC (alg (R (handleCoercible other)))

    L (GetCurrentUser k) -> do
      rt <- SthenauthC ask
      liftIO (readIORef (rt ^. tstate.user)) >>= k

    L (SetCurrentUser key k) -> do
      rt <- SthenauthC ask
      cu <- unwrap
        (currentUserFromSessionKey (rt ^. env.policy) (rt ^. currentTime) key)
        <&> fromRight notLoggedIn
      liftIO (writeIORef (rt ^. tstate.user) cu)
      k cu

    L (CreateAccount creds k) ->
      runRequestAuthN (Auth.CreateLocalAccountWithCredentials creds) >>= k

    L (LoginWithCredentials creds k) ->
      runRequestAuthN (Auth.LoginWithLocalCredentials creds) >>= k

    L (LoginWithOidcProvider url login k) ->
      runRequestAuthN (Auth.LoginWithOidcProvider url login) >>= k

    L (FinishLoginWithOidcProvider url user k) ->
      runRequestAuthN (Auth.FinishLoginWithOidcProvider url user) >>= k

    L (ProcessFailedOidcProviderLogin e k) ->
      runRequestAuthN (Auth.ProcessFailedOidcProviderLogin e) >>= k

    L (Logout k) -> do
      rt <- SthenauthC ask
      runRequestAuthN Auth.Logout >>= \case
        Right (Just c, _) -> k c
        _ -> do
          -- Ignore errors and force a logout:
          liftIO (writeIORef (rt ^. tstate.user) notLoggedIn)
          k $ resetSessionCookie (sessionCookieName (rt ^. env.policy))

    L (RegisterOidcProvider kp oi op k) ->
      requireAdmin k $ unwrap (OIDC.registerOidcProvider http kp oi op)

    where
      requireAdmin k action = do
        rt <- SthenauthC ask
        user <- liftIO (readIORef (rt ^. tstate.user))
        if isAdmin user
          then action >>= k
          else k (Left $ ApplicationUserError PermissionDenied)

--------------------------------------------------------------------------------
runRequestAuthN
  :: (MonadIO m, Algebra sig m)
  => Auth.RequestAuthN
  -> SthenauthC m (Either Sterr (Maybe SetCookie, Auth.ResponseAuthN))
runRequestAuthN req = do
  rt <- SthenauthC ask
  withUser (Auth.requestAuthN (rt ^. env.policy) (rt ^. tstate.remote) req)

--------------------------------------------------------------------------------
-- | A type to help discharge all of the effects used in this library.
type Action m =
    ReaderC Runtime
      (DatabaseC
        (CryptoC
          (HttpC
            (ErrorC Sterr
              (LiftC m)))))

--------------------------------------------------------------------------------
-- | Discharge all of the effects used in Sthenauth.
unwrap
  :: (MonadIO m, Algebra sig m)
  => Action RIO a
  -> SthenauthC m (Either Sterr a)
unwrap a = do
  rt <- SthenauthC ask
  liftRIO rt a

--------------------------------------------------------------------------------
-- | Unwrap an action that expects a current user as a state field.
withUser
  :: (MonadIO m, Algebra sig m)
  => StateC CurrentUser (Action RIO) a
  -> SthenauthC m (Either Sterr a)
withUser a = do
  rt <- SthenauthC ask
  cu <- liftIO (readIORef (rt ^. tstate.user))
  unwrap (runState cu a) >>= \case
    Left e -> pure (Left e)
    Right (cu', x) -> do
      liftIO (writeIORef (rt ^. tstate.user) cu')
      pure (Right x)

--------------------------------------------------------------------------------
-- | This delightful hack works around an orphan instance for
-- MonadRandom in the JOSE package.
newtype RIO a = RIO
  { unRIO :: forall sig m. (MonadIO m, Algebra sig m)
          => ReaderC Crypto.Runtime m a
  }

instance Functor RIO where
  fmap f (RIO r) = RIO (fmap f r)

instance Applicative RIO where
  pure x = RIO (pure x)
  (<*>) (RIO f) (RIO x) = RIO (f <*> x)

instance Monad RIO where
  (>>=) (RIO x) f = RIO (x >>= \y -> let RIO r = f y in r)

instance MonadIO RIO where
  liftIO x = RIO (liftIO x)

instance MonadRandom RIO where
  getRandomBytes n = RIO $ do
    c <- ask <&> Crypto.cryptonite
    Crypto.randomBytesFromCryptonite c n

--------------------------------------------------------------------------------
liftRIO
  :: (MonadIO m, Algebra sig m)
  => Runtime
  -> Action RIO a
  -> SthenauthC m (Either Sterr a)
liftRIO rt rio
    = runReader rt rio
    & runDatabase (rt ^. env.database)
    & runCrypto (rt ^. env.crypto)
    & runHTTP (rt ^. env.httpr)
    & runError
    & runM
    & unRIO
    & runReader (rt ^. env.crypto)

--------------------------------------------------------------------------------
-- | An escape hatch that creates a local account with administrator
-- privileges.  If there are existing administrator accounts this
-- function will fail with a 'PermissionDenied' error.
createInitialAdminAccount
  :: MonadIO m
  => Environment
  -> Credentials
  -> m (Either Sterr AccountId)
createInitialAdminAccount env creds = do
  now <- liftIO getCurrentTime
  go now
    & runDatabase (env ^. database)
    & runCrypto (env ^. crypto)
    & runError
    & runM
  where
    go now = do
      whenM (runQuery (Query.count Admin.fromAdmins) <&> (/= 0)) $
        throwUserError PermissionDenied

      query <- insertLocalAccountQuery (env ^. policy) now creds
      transaction $ do
        acct <- query
        Just _ <- Admin.insertAdmin (accountId acct)
        pure (accountId acct)

--------------------------------------------------------------------------------
-- | Per-request entry point.
--
-- Each thread that calls into this function maintains its own state
-- regarding details such as the current user and remote endpoint
-- making the request.
--
-- Typical flow through this library:
--
--   1. 'initSthenauth'
--
--   2. On first run, call 'createInitialAdminAccount'
--
--   3. Each authentication request thread calls 'runSthenauth'.
runSthenauth
  :: MonadIO m
  => Environment
  -> Remote
  -> SthenauthC m a
  -> m a
runSthenauth e r m = do
  cu <- liftIO (newIORef notLoggedIn)
  let st = TState cu r
  runReader (Runtime e st) (runSthenauthC m)
