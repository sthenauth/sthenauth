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
module Sthenauth.Shell.Command
  ( Command
  , runCommand
  , runBootCommand
  , currentSite
  , currentConfig
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Control.Carrier.Database (runDatabase)
import Control.Carrier.Error.Either (runError)
import Crypto.Random (MonadRandom(..))
import Data.Time.Clock (getCurrentTime)
import Sthenauth.Core.Action
import Sthenauth.Core.Address (localhost)
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Error
import Sthenauth.Core.Remote
import Sthenauth.Core.Runtime
import Sthenauth.Core.Site (Site, siteFqdn, siteFromFQDN)
import Sthenauth.Crypto.Effect
import Sthenauth.Shell.AuthN
import Sthenauth.Shell.Options (Options, site)

--------------------------------------------------------------------------------
-- | A type encapsulating Sthenauth shell commands.
newtype Command a = Command { unC :: Action IO a }
  deriving newtype
    ( Functor, Applicative, Monad
    , MonadByline
    )

--------------------------------------------------------------------------------
instance MonadIO Command where
  liftIO = Command . lift . liftIO

instance Algebra (ActionEff IO) Command where
  alg = Command . alg . handleCoercible

instance MonadRandom Command where
  getRandomBytes = randomByteArray

--------------------------------------------------------------------------------
runCommand
  :: forall o a.
     Options o
  -> Runtime
  -> Command a
  -> IO (Either BaseError a)
runCommand opts env cmd =
    runBootCommand opts env go
  where
    go :: Command a
    go = do
      site <- asks currentSite
      remote <- asks currentRemote
      user <- authenticate opts site remote
      unless (isAdmin user) (throwUserError PermissionDenied)
      cmd -- Run the original action.

--------------------------------------------------------------------------------
-- | Execute a command without any authentication.
runBootCommand
  :: Options o
  -> Runtime
  -> Command a
  -> IO (Either BaseError a)
runBootCommand opts env cmd =
  findSiteFromOptions >>= \case
    Left e -> pure (Left e)
    Right site -> do
      remote <- mkRemote site
      snd <<$>> runAction env site remote notLoggedIn (unC cmd)

  where
    findSiteFromOptions :: IO (Either BaseError Site)
    findSiteFromOptions
      = runDatabase (rtDb env) (siteFromFQDN (site opts))
      & runError

    mkRemote :: Site -> IO Remote
    mkRemote site = do
      rid <- genRequestId
      time <- liftIO getCurrentTime

      return Remote
        { _address     = localhost
        , _userAgent   = "Sthenauth Command Line"
        , _requestFqdn = siteFqdn site
        , _requestId   = rid
        , _requestTime = time
        }