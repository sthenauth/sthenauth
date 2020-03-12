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
module Sthenauth.Providers.OIDC.Effect
  ( OIDC(..)
  , providerDiscovery
  , getRedirectUrl
  -- , getEmailToken

    -- * Re-exports
  , Algebra
  , Effect
  , Has
  , run
  ) where

--------------------------------------------------------------------------------
import Control.Algebra
import Network.URI (URI)
import Sthenauth.Core.Session (ClearSessionKey)
import Sthenauth.Core.Site (Site)
import Sthenauth.Providers.OIDC.Provider

data OIDC m k
  = ProviderDiscovery Site Provider (() -> m k)
  | GetRedirectUrl ClearSessionKey (URI -> m k)
  -- | GetEmailToken Partial Details (EmailToken -> m k)
  deriving stock (Generic1, Functor)
  deriving anyclass (HFunctor, Effect)

--------------------------------------------------------------------------------
providerDiscovery :: Has OIDC sig m => Site -> Provider -> m ()
providerDiscovery s p = send (ProviderDiscovery s p pure)

--------------------------------------------------------------------------------
getRedirectUrl :: Has OIDC sig m => ClearSessionKey -> m URI
getRedirectUrl c = send (GetRedirectUrl c  pure)

--------------------------------------------------------------------------------
-- getEmailToken :: Has OIDC sig m => Partial -> Details -> m EmailToken
-- getEmailToken p d = send (GetEmailToken p d pure)
