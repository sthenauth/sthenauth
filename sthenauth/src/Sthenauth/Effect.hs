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
module Sthenauth.Effect
  ( Sthenauth
  , getCapabilities
  , getCurrentUser
  , setCurrentUser
  , getCurrentRemote
  , createAccountEither
  , createAccount
  , loginWithCredentialsEither
  , loginWithCredentials
  , loginWithOidcProviderEither
  , loginWithOidcProvider
  , finishLoginWithOidcProviderEither
  , finishLoginWithOidcProvider
  , processFailedOidcProviderLoginEither
  , processFailedOidcProviderLogin
  , logout

    -- * Administrator commands
  , registerOidcProviderEither
  , registerOidcProvider
  , modifySiteEither
  , modifySite
  , modifySitePolicyEither
  , modifySitePolicy
  , alterAccountAdminStatusEither
  , alterAccountAdminStatus

    -- * Re-exports
  , module Sthenauth.Core.AuthN
  , module Sthenauth.Core.Capabilities
  , module Sthenauth.Core.CurrentUser
  , module Sthenauth.Core.Policy
  , module Sthenauth.Core.Session
  , module Sthenauth.Core.Site
  , module Sthenauth.Core.URL
  , module Sthenauth.Providers.OIDC
  , module Sthenauth.Core.Admin
  , module Sthenauth.Providers.Local
  , module Web.Cookie

  , Algebra
  , Effect
  , Has
  , run
  ) where

import Web.Cookie (SetCookie)

import Sthenauth.Core.Admin (AlterAdmin(..))
import Sthenauth.Core.Capabilities (Capabilities(..))
import Sthenauth.Core.Policy
import Sthenauth.Core.Site (SiteF(..), Site)
import Sthenauth.Effect.Algebra
import Sthenauth.Providers.Local (Login(..), Credentials(..), toLogin)
import Sthenauth.Providers.OIDC

import Sthenauth.Core.URL
  (URL, getURI, textToURL, strToURL, urlFromFQDN, urlFromURI)

import Sthenauth.Core.CurrentUser
  (CurrentUser, recordUserActivity, toAccount)
import Sthenauth.Core.Session
  (ClearSessionKey)

import Sthenauth.Core.AuthN
  (ResponseAuthN(..))
