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
module Sthenauth.Effect.Algebra
  ( Sthenauth(..)
  , getCapabilitiesEither
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
  , registerOidcProviderEither
  , registerOidcProvider
  ) where

--------------------------------------------------------------------------------
import Control.Algebra
import GHC.Generics (Generic1)
import Sthenauth.Core.AuthN (ResponseAuthN)
import Sthenauth.Core.Capabilities (Capabilities)
import Sthenauth.Core.CurrentUser (CurrentUser)
import Sthenauth.Core.Error (Sterr)
import Sthenauth.Core.Remote (Remote)
import Sthenauth.Core.Session (ClearSessionKey)
import Sthenauth.Core.URL (URL)
import Sthenauth.Providers.Local.Provider (Credentials)
import Sthenauth.Providers.OIDC
import Web.Cookie (SetCookie)

--------------------------------------------------------------------------------
type AuthRes = Either Sterr (Maybe SetCookie, ResponseAuthN)

--------------------------------------------------------------------------------
data Sthenauth m k
  = GetCapabilities (Either Sterr Capabilities -> m k)
  | GetCurrentUser (CurrentUser -> m k)
  | SetCurrentUser ClearSessionKey (CurrentUser -> m k)
  | GetCurrentRemote (Remote -> m k)
  | CreateAccount Credentials (AuthRes -> m k)
  | LoginWithCredentials Credentials (AuthRes -> m k)
  | LoginWithOidcProvider URL OidcLogin (AuthRes -> m k)
  | FinishLoginWithOidcProvider URL UserReturnFromRedirect (AuthRes -> m k)
  | ProcessFailedOidcProviderLogin IncomingOidcProviderError (AuthRes -> m k)
  | Logout (SetCookie -> m k)

  | RegisterOidcProvider
      KnownOidcProvider
      OidcClientId
      OidcClientPassword
      (Either Sterr OidcProvider -> m k)
  deriving stock (Generic1, Functor)
  deriving anyclass (HFunctor, Effect)

--------------------------------------------------------------------------------
-- | Access the capabilities of this Sthenauth instance.
getCapabilitiesEither :: Has Sthenauth sig m => m (Either Sterr Capabilities)
getCapabilitiesEither = send (GetCapabilities pure)

--------------------------------------------------------------------------------
getCapabilities
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => m Capabilities
getCapabilities = getCapabilitiesEither >>= either throwError pure

--------------------------------------------------------------------------------
-- | Access the current user.
getCurrentUser :: Has Sthenauth sig m => m CurrentUser
getCurrentUser = send (GetCurrentUser pure)

--------------------------------------------------------------------------------
-- | Set the current user given a session key.
setCurrentUser :: Has Sthenauth sig m => ClearSessionKey -> m CurrentUser
setCurrentUser = send . (`SetCurrentUser` pure)

--------------------------------------------------------------------------------
-- | Access the current remote user information.
getCurrentRemote :: Has Sthenauth sig m => m Remote
getCurrentRemote = send (GetCurrentRemote pure)

--------------------------------------------------------------------------------
-- | Create a new, local account.  Uses 'Either' to handle errors.
createAccountEither
  :: Has Sthenauth sig m
  => Credentials
  -> m (Either Sterr (Maybe SetCookie, ResponseAuthN))
createAccountEither = send . (`CreateAccount` pure)

--------------------------------------------------------------------------------
-- | Create a new, local account.  Uses 'throwError' to handle errors.
createAccount
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => Credentials
  -> m (Maybe SetCookie, ResponseAuthN)
createAccount = createAccountEither >=> either throwError pure

--------------------------------------------------------------------------------
-- | Attempt to login using the provided credentials.
--
-- Regardless of the response, if a 'SetCookie' value is returned you
-- should pass that cookie off to the end-user.
loginWithCredentialsEither
  :: Has Sthenauth sig m
  => Credentials
  -> m (Either Sterr (Maybe SetCookie, ResponseAuthN))
loginWithCredentialsEither = send . (`LoginWithCredentials` pure)

--------------------------------------------------------------------------------
-- | Similar to 'loginWithCredentialsEither' except errors are
-- processed with 'throwError'.
loginWithCredentials
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => Credentials
  -> m (Maybe SetCookie, ResponseAuthN)
loginWithCredentials =
  loginWithCredentialsEither
    >=> either throwError pure

--------------------------------------------------------------------------------
-- | Attempt to login using a previously configured OIDC provider.
--
-- Regardless of the response, if a 'SetCookie' value is returned you
-- should pass that cookie off to the end-user.
loginWithOidcProviderEither
  :: Has Sthenauth sig m
  => URL
  -> OidcLogin
  -> m (Either Sterr (Maybe SetCookie, ResponseAuthN))
loginWithOidcProviderEither url login =
  send (LoginWithOidcProvider url login pure)

--------------------------------------------------------------------------------
-- | Similar to 'loginWithOidcProviderEither' except errors are
-- processed with 'throwError'.
loginWithOidcProvider
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => URL
  -> OidcLogin
  -> m (Maybe SetCookie, ResponseAuthN)
loginWithOidcProvider url =
  loginWithOidcProviderEither url
    >=> either throwError pure

--------------------------------------------------------------------------------
-- | Process the provider response.
--
-- NOTE: The cookie data in the 'UserReturnFromRedirect' value can be
-- an entire @Cookie:@ header.  In that case just the OIDC cookie is
-- extracted and passed along to the OpenID Connect library.
finishLoginWithOidcProviderEither
  :: Has Sthenauth sig m
  => URL
  -> UserReturnFromRedirect
  -> m (Either Sterr (Maybe SetCookie, ResponseAuthN))
finishLoginWithOidcProviderEither url user =
  send (FinishLoginWithOidcProvider url user pure)

--------------------------------------------------------------------------------
finishLoginWithOidcProvider
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => URL
  -> UserReturnFromRedirect
  -> m (Maybe SetCookie, ResponseAuthN)
finishLoginWithOidcProvider url =
  finishLoginWithOidcProviderEither url
    >=> either throwError pure

--------------------------------------------------------------------------------
-- | Process a failed provider login.
--
-- NOTE: The cookie data in the 'IncomingOidcProviderError' value can
-- be an entire @Cookie:@ header.  In that case just the OIDC cookie
-- is extracted and passed along to the OpenID Connect library.
processFailedOidcProviderLoginEither
  :: Has Sthenauth sig m
  => IncomingOidcProviderError
  -> m (Either Sterr (Maybe SetCookie, ResponseAuthN))
processFailedOidcProviderLoginEither =
  send . (`ProcessFailedOidcProviderLogin` pure)

--------------------------------------------------------------------------------
processFailedOidcProviderLogin
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => IncomingOidcProviderError
  -> m (Maybe SetCookie, ResponseAuthN)
processFailedOidcProviderLogin =
  processFailedOidcProviderLoginEither
    >=> either throwError pure

--------------------------------------------------------------------------------
-- | Log a user out.  The provided 'SetCookie' should be sent to the
-- end-user to erase the session cookie they have.
logout :: Has Sthenauth sig m => m SetCookie
logout = send (Logout pure)

--------------------------------------------------------------------------------
-- | Register a new OIDC provider.
--
-- The current user /must/ be an administrator otherwise this call
-- will fail with a permission denied error.
registerOidcProviderEither
  :: Has Sthenauth sig m
  => KnownOidcProvider             -- ^ Provider details
  -> OidcClientId                  -- ^ The provider-assigned client ID
  -> OidcClientPassword            -- ^ The provider-assigned client credentials
  -> m (Either Sterr OidcProvider) -- ^ New provider record
registerOidcProviderEither kp oi op =
  send (RegisterOidcProvider kp oi op pure)

--------------------------------------------------------------------------------
-- | Register a new OIDC provider.
--
-- The current user /must/ be an administrator otherwise this call
-- will fail with a permission denied error.
registerOidcProvider
  :: ( Has Sthenauth     sig m
     , Has (Throw Sterr) sig m
     )
  => KnownOidcProvider             -- ^ Provider details
  -> OidcClientId                  -- ^ The provider-assigned client ID
  -> OidcClientPassword            -- ^ The provider-assigned client credentials
  -> m OidcProvider                -- ^ New provider record.
registerOidcProvider k o =
  registerOidcProviderEither k o
    >=> either throwError pure
