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

  , Details(..)

  -- , EmailToken
  -- , EmailClaim(..)
  -- , tokenSubject

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
import Sthenauth.Providers.OIDC.Session
import qualified Web.OIDC.Client as WebOIDC

--------------------------------------------------------------------------------
newtype Details = Details (Provider, WebOIDC.OIDC)

--------------------------------------------------------------------------------
data OIDC m k
  = ProviderDiscovery Site Provider (Details -> m k)
  | GetRedirectUrl ClearSessionKey Partial Details (URI -> m k)
  -- | GetEmailToken Partial Details (EmailToken -> m k)
  deriving stock (Generic1, Functor)
  deriving anyclass (HFunctor, Effect)

--------------------------------------------------------------------------------
providerDiscovery :: Has OIDC sig m => Site -> Provider -> m Details
providerDiscovery s p = send (ProviderDiscovery s p pure)

--------------------------------------------------------------------------------
getRedirectUrl :: Has OIDC sig m => ClearSessionKey -> Partial -> Details -> m URI
getRedirectUrl c p d = send (GetRedirectUrl c p d pure)

--------------------------------------------------------------------------------
-- getEmailToken :: Has OIDC sig m => Partial -> Details -> m EmailToken
-- getEmailToken p d = send (GetEmailToken p d pure)
