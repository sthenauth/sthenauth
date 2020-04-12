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
  , getCurrentUser
  , setCurrentUser
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

  , registerOidcProviderEither
  , registerOidcProvider

    -- * Re-exports
  , module Sthenauth.Core.AuthN
  , module Sthenauth.Core.CurrentUser
  , module Sthenauth.Core.Session
  , module Sthenauth.Core.URL
  , module Sthenauth.Providers.Local.Provider
  , module Sthenauth.Providers.OIDC
  , module Web.Cookie

  , Algebra
  , Effect
  , Has
  , run
  ) where

import Web.Cookie (SetCookie)

import Sthenauth.Effect.Algebra
import Sthenauth.Providers.OIDC

import Sthenauth.Core.URL
  (URL, getURI, textToURL, strToURL, urlFromFQDN, urlFromURI)

import Sthenauth.Core.CurrentUser
  (CurrentUser, recordUserActivity, toAccount)

import Sthenauth.Core.Session
  (ClearSessionKey)

import Sthenauth.Core.AuthN
  (ResponseAuthN(..))

import Sthenauth.Providers.Local.Provider
  (Credentials(..))
