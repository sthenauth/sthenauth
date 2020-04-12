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
module Sthenauth.Providers.OIDC
  ( OidcLogin(..)
  , IncomingOidcProviderError(..)

  , OidcProvider
  , OidcClientId
  , OidcClientPassword(..)
  , OidcPublicProvider

  , KnownOidcProvider
  , loadKnownOidcProviders

  , UserReturnFromRedirect(..)
  ) where

--------------------------------------------------------------------------------
import OpenID.Connect.Client.Flow.AuthorizationCode (UserReturnFromRedirect(..))
import Sthenauth.Providers.OIDC.AuthN
import Sthenauth.Providers.OIDC.Known
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Providers.OIDC.Public

--------------------------------------------------------------------------------
type OidcProvider = Provider

--------------------------------------------------------------------------------
type OidcPublicProvider = Public
