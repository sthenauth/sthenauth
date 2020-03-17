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
module Sthenauth.Core.AuthN
  ( RequestAuthN(..)
  , ResponseAuthN(..)
  , AdditionalStep(..)
  , requestAuthN
  , logout

  , OIDC.IncomingOidcProviderError(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Iolaus.Database.Table (getKey)
import qualified OpenID.Connect.Client.Flow.AuthorizationCode as OIDC
import Sthenauth.Core.Account (accountId)
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Error
import Sthenauth.Core.Event
import Sthenauth.Core.EventDetail
import Sthenauth.Core.HTTP
import Sthenauth.Core.Policy
import Sthenauth.Core.PostLogin
import Sthenauth.Core.Provider (ProviderType(..))
import Sthenauth.Core.Remote
import Sthenauth.Core.Session
import Sthenauth.Core.Site (Site, sessionCookieName, sitePolicy)
import Sthenauth.Core.URL
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import qualified Sthenauth.Providers.Local.Provider as Local
import qualified Sthenauth.Providers.OIDC.AuthN as OIDC
import Sthenauth.Providers.Types
import Web.Cookie

--------------------------------------------------------------------------------
data RequestAuthN
  = LoginWithLocalCredentials Local.Credentials
  | CreateLocalAccountWithCredentials  Local.Credentials
  | LoginWithOidcProvider URL OIDC.OidcLogin
  | FinishLoginWithOidcProvider URL OIDC.UserReturnFromRedirect
  | ProcessFailedOidcProviderLogin OIDC.IncomingOidcProviderError

--------------------------------------------------------------------------------
data ResponseAuthN
  = LoggedIn SetCookie PostLogin
  | NextStep AdditionalStep
  | LoggedOut (Maybe SetCookie)

--------------------------------------------------------------------------------
-- | Authenticate a user with the given provider.
requestAuthN
  :: ( Has Error               sig m
     , Has Crypto              sig m
     , Has HTTP                sig m
     , Has Database            sig m
     , Has (State CurrentUser) sig m
     , MonadRandom                 m
     )
  => Site
  -> Remote
  -> RequestAuthN
  -> m ResponseAuthN
requestAuthN site remote req = do
  void (logout site remote)

  dispatchRequest site remote req >>= \case
    ProcessAdditionalStep step ->
      pure (NextStep step)

    SuccessfulAuthN account status -> do
      -- Fire events
      (sess, key, postLogin) <- issueSession site remote account
      user <- currentUserFromSession site (remote ^. requestTime) account sess
      put user

      fireEvents user remote $ catMaybes
        [ case status of
            ExistingAccount -> Nothing
            NewAccount -> Just . EventAccountCreated . getKey . accountId $ account

        , Just (EventSuccessfulLogin postLogin)
        ]

      let cookie = makeSessionCookie (sessionCookieName site) key sess
      pure (LoggedIn cookie postLogin)

    SuccessfulLogout cookie ->
      let c = cookie <|> Just (resetSessionCookie $ sessionCookieName site)
      in pure (LoggedOut c)

    FailedAuthN ue detail -> do
      user <- get
      fireEvents user remote [detail]
      throwUserError ue

--------------------------------------------------------------------------------
-- | Delete the current user's session.
logout
  :: ( Has Database            sig m
     , Has Error               sig m
     , Has (State CurrentUser) sig m
     )
  => Site
  -> Remote
  -> m SetCookie
logout site remote = do
  user <- get
  case sessionFromCurrentUser user of
    Nothing -> pure reset
    Just session -> do
      -- | FIXME: give the provider a chance to clean up session
      -- details then delete the session object.
      fireEvents user remote [EventLogout . getKey $ sessionAccountId session]
      runQuery (deleteSession (sessionId session))

      put notLoggedIn
      pure reset
  where
    reset :: SetCookie
    reset = resetSessionCookie (sessionCookieName site)

--------------------------------------------------------------------------------
dispatchRequest
  :: forall sig m.
     ( Has Crypto   sig m
     , Has Database sig m
     , Has HTTP     sig m
     , Has Error    sig m
     , MonadRandom      m
     )
  => Site
  -> Remote
  -> RequestAuthN
  -> m ProviderResponse
dispatchRequest site remote = \case
  LoginWithLocalCredentials creds -> do
    assertPolicyRules (sitePolicy site)
      [ policyAllowsProviderType LocalProvider
      ]
    catchError (Local.authenticate site remote creds)
               (onLocalError creds)

  CreateLocalAccountWithCredentials creds -> do
    assertPolicyRules (sitePolicy site)
      [ policyAllowsProviderType LocalProvider
      , policyAllowsLocalAccountCreation
      ]
    catchError (Local.createNewLocalAccount site remote creds)
               (onLocalError creds)

  LoginWithOidcProvider url login -> do
    assertPolicyRules (sitePolicy site)
      [ policyAllowsProviderType OidcProvider
      ]
    catchError
      (OIDC.requestOIDC site remote (OIDC.LoginWithOidcProvider url login))
      (onOidcError (show login))

  FinishLoginWithOidcProvider url browser -> do
    assertPolicyRules (sitePolicy site)
      [ policyAllowsProviderType OidcProvider
      ]
    catchError
      (OIDC.requestOIDC site remote (OIDC.SuccessfulReturnFromProvider url browser))
      (onOidcError "unavailable: browser return from OIDC provider authN")

  ProcessFailedOidcProviderLogin failure ->
    OIDC.requestOIDC site remote (OIDC.FailedReturnFromProvider failure)

  where
    onLocalError :: Local.Credentials -> BaseError -> m ProviderResponse
    onLocalError creds = \case
      ApplicationUserError ue ->
        FailedAuthN ue <$> failedLoginEvent ue (Local.name creds)
      e -> throwError e

    onOidcError :: Text -> BaseError -> m ProviderResponse
    onOidcError ident = \case
      ApplicationUserError ue -> FailedAuthN ue <$> failedLoginEvent ue ident
      e                       -> throwError e

    failedLoginEvent
      :: UserError
      -> Text
      -> m EventDetail
    failedLoginEvent ue username = do
        safeName <- encrypt username
        pure (EventFailedLogin safeName (accountFromError ue))

      where
        accountFromError :: UserError -> Maybe UUID
        accountFromError = \case
          AuthenticationFailedError u -> u
          _                           -> Nothing
