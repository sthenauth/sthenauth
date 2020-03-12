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
module Sthenauth.Providers.Types
  ( ProviderResponse(..)
  , AdditionalStep(..)
  , AccountStatus(..)
  , ProviderType(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Sthenauth.Core.Account (Account)
import Sthenauth.Core.Error
import Sthenauth.Core.EventDetail
import Sthenauth.Core.URL
import Web.Cookie

--------------------------------------------------------------------------------
-- | How a provider can respond to a request.
data ProviderResponse
  = ProcessAdditionalStep AdditionalStep
    -- ^ Another step in the authentication process is required.

  | SuccessfulAuthN Account AccountStatus
    -- ^ The end-user has successfully authenticated.

  | FailedAuthN UserError EventDetail
    -- ^ The end-user failed authentication.

--------------------------------------------------------------------------------
data AdditionalStep
  = RedirectTo URL SetCookie
    -- ^ Send the end-user to the given URL, setting a cookie.

--------------------------------------------------------------------------------
-- | The status of an account being returned from authentication.
data AccountStatus
  = NewAccount       -- ^ The account was just created.
  | ExistingAccount  -- ^ The account already existed.

--------------------------------------------------------------------------------
-- | The types of providers supported.  This is used to control which
-- providers are allowed based on site policy.
data ProviderType
  = LocalProvider
    -- ^ Local accounts.

  | OidcProvider
    -- ^ Accounts provided by an OpenID Connect provider.
