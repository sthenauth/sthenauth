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
module Sthenauth.Providers.OIDC.AuthN
  ( RequestOIDC(..)
  , OidcLogin(..)
  , IncomingOidcProviderError(..)
  , requestOIDC
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((^.))
import Crypto.JWT (ClaimsSet)
import qualified Data.Aeson as Aeson
import Data.Time.Clock (UTCTime)
import Data.UUID (UUID)
import qualified Generics.SOP as SOP
import Iolaus.Database.JSON
import Iolaus.Database.Query
import Iolaus.Database.Table (Key(..))
import qualified OpenID.Connect.Client.Flow.AuthorizationCode as OIDC
import OpenID.Connect.TokenResponse (TokenResponse)
import qualified OpenID.Connect.TokenResponse as TR
import Relude.Monad.Reexport (MaybeT(..), runMaybeT) -- FIXME: remove this at some point
import Sthenauth.Core.Account
import Sthenauth.Core.Crypto
import Sthenauth.Core.Database
import Sthenauth.Core.Encoding
import Sthenauth.Core.Error
import Sthenauth.Core.EventDetail
import Sthenauth.Core.HTTP
import Sthenauth.Core.Policy
import Sthenauth.Core.Remote
import Sthenauth.Core.Site (SiteF(..), Site, SiteId)
import Sthenauth.Core.URL
import Sthenauth.Providers.OIDC.Account
import Sthenauth.Providers.OIDC.Cookie
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Providers.Types
import Web.Cookie (SetCookie)

--------------------------------------------------------------------------------
data IncomingOidcProviderError = IncomingOidcProviderError
  { oidcSessionCookieValue :: ByteString
    -- ^ The cookie value that was set when redirecting to the provider.
  , oidcErrorParam :: Text
    -- ^ The @error@ query parameter.
  , oidcErrorDescriptionParam :: Maybe Text
    -- ^ The @error_description@ query parameter.
  } deriving (Show, Exception)

--------------------------------------------------------------------------------
newtype OidcLogin = OidcLogin
  { remoteProviderId :: UUID
  }
  deriving stock (Generic, Show)
  deriving anyclass (SOP.Generic, SOP.HasDatatypeInfo)
  deriving (ToJSON, FromJSON) via GenericJSON OidcLogin
  deriving ( HasElmType
           , HasElmEncoder Aeson.Value
           , HasElmDecoder Aeson.Value
           ) via GenericElm "OidcLogin" OidcLogin

--------------------------------------------------------------------------------
-- | Requests that can be processed by this module.
data RequestOIDC
  = LoginWithOidcProvider URL OidcLogin
  | SuccessfulReturnFromProvider URL OIDC.UserReturnFromRedirect
  | FailedReturnFromProvider IncomingOidcProviderError
  | BackendLogout AccountId

--------------------------------------------------------------------------------
-- | Process a request.
requestOIDC
  :: ( Has Database      sig m
     , Has Crypto        sig m
     , Has HTTP          sig m
     , Has (Throw Sterr) sig m
     , MonadRandom           m
     )
  => Site
  -> Remote
  -> RequestOIDC
  -> m ProviderResponse
requestOIDC site remote = \case
  LoginWithOidcProvider url login ->
    startProviderLogin site remote url login
  SuccessfulReturnFromProvider url browser ->
    returnFromProvider site remote url browser
  FailedReturnFromProvider perror ->
    authenticationFailed (siteId site) perror
  BackendLogout _ ->
    -- FIXME: Update this when we support backend logout.
    pure (SuccessfulLogout Nothing)

--------------------------------------------------------------------------------
-- | Initiate a authentication session with an OIDC provider by
-- sending the end-user to their authorization end-point.
startProviderLogin
  :: forall sig m.
     ( Has Database      sig m
     , Has Crypto        sig m
     , Has HTTP          sig m
     , Has (Throw Sterr) sig m
     , MonadRandom           m
     )
  => Site
  -> Remote
  -> URL
  -> OidcLogin
  -> m ProviderResponse
startProviderLogin site remote url (OidcLogin uuid) = do
  provider <- fetchProvider >>= refreshProvider (remote ^. requestTime)
  req <- authReq provider
  OIDC.authenticationRedirect
    (unliftJSON (providerDiscoveryDoc provider)) req >>= \case
      Left e  -> throwError (OidcProviderError (SomeException e))
      Right (OIDC.RedirectTo uri cookief) -> do
        let cookie = cookief (encodeUtf8 (oidcCookieName $ sitePolicy site))
        saveCookie provider cookie
        pure (ProcessAdditionalStep (RedirectTo (urlFromURI uri)) (Just cookie))

  where
    fetchProvider :: m Provider
    fetchProvider = runQuery $ do
      Just provider <- select1 (providerById (Key uuid))
      pure provider

    authReq :: Provider -> m OIDC.AuthenticationRequest
    authReq provider =
      OIDC.defaultAuthenticationRequest (OIDC.openid <> OIDC.email)
        <$> providerCredentials url provider

    saveCookie :: Provider -> SetCookie -> m ()
    saveCookie provider cookie = do
      query <- newOidcCookie site
          (remote ^. requestTime) cookie (providerId provider)
      transaction $ do
        1 <- insert query
        pass

--------------------------------------------------------------------------------
-- | Successful return from a provider.
returnFromProvider
  :: forall sig m.
     ( Has Database      sig m
     , Has Crypto        sig m
     , Has HTTP          sig m
     , Has (Throw Sterr) sig m
     , MonadRandom           m
     )
  => Site
  -> Remote
  -> URL
  -> OIDC.UserReturnFromRedirect
  -> m ProviderResponse
returnFromProvider site remote url browser = do
  (cookie, provider) <- findSessionCookie (siteId site)
    (OIDC.afterRedirectSessionCookie browser)
  runQuery_ (delete (deleteOidcCookie cookie))
  creds <- providerCredentials url provider
  OIDC.authenticationSuccess http (remote ^. requestTime)
    (toOidcProvider provider) creds browser >>= \case
      Left e -> throwError (OidcProviderError (SomeException e))
      Right token -> loginFromToken provider token

  where

    ----------------------------------------------------------------------------
    -- If an account for the given token exists, return it.  This
    -- function updates the OIDC account and any email addresses.
    findAccountsFromToken
      :: Provider
      -> TokenResponse ClaimsSet
      -> m (Maybe Account)
    findAccountsFromToken provider token = runMaybeT $ do
      let claims = TR.idToken token
          time   = remote ^. requestTime
      query <- hoistMaybe (selectAccountsByClaims (siteId site) (providerId provider) claims)
      (acct, oacct) <- MaybeT $ runQuery (select1 query)
      (upAcct, insEmail) <- lift (updateAccountFromToken oacct time token)
      lift . transaction $ do
        _ <- update upAcct
        traverse_ insert insEmail
        pure acct

    ----------------------------------------------------------------------------
    -- Creates a new set of accounts, returning the core account type.
    createAccounts
      :: Provider
      -> TokenResponse ClaimsSet
      -> m Account
    createAccounts provider token =
      newOidcAccount (siteId site) (providerId provider)
        (remote ^. requestTime) token >>= \case
          (Nothing, _) -> throwError OidcProviderInvalidClaimsSet
          (Just oai, emailm) -> transaction $ do
            Just account <- insert1 (newAccount (siteId site) Nothing)
            1 <- insert (oai (accountId account))
            traverse_ insert (emailm <*> pure (accountId account))
            pure account

    ----------------------------------------------------------------------------
    -- Fetch an existing account, or create a new one.
    loginFromToken
      :: Provider
      -> TokenResponse ClaimsSet
      -> m ProviderResponse
    loginFromToken provider token =
      findAccountsFromToken provider token >>= \case
        Just acct -> pure (SuccessfulAuthN acct ExistingAccount)
        Nothing -> do
          acct <- createAccounts provider token
          pure (SuccessfulAuthN acct NewAccount)

--------------------------------------------------------------------------------
-- | Respond to the a failed authentication from the OIDC provider.
authenticationFailed
  :: ( Has Database      sig m
     , Has Crypto        sig m
     , Has (Throw Sterr) sig m
     )
  => SiteId
  -> IncomingOidcProviderError
  -> m ProviderResponse
authenticationFailed sid perror = do
    (cookie, provider) <- findSessionCookie sid (oidcSessionCookieValue perror)
    runQuery_ (delete $ deleteOidcCookie cookie)
    pure (FailedAuthN OidcProviderAuthenticationFailed (details provider))
  where
    details :: Provider -> EventDetail
    details p =
      EventFailedOidcProviderAuth
        { attemptedProviderId = getKey (providerId p)
        , providerErrorCode   = oidcErrorParam perror
        , providerErrorDesc   = oidcErrorDescriptionParam perror
        }

--------------------------------------------------------------------------------
-- | Reload the provider's cache if needed.
refreshProvider
  :: ( Has Database      sig m
     , Has HTTP          sig m
     , Has (Throw Sterr) sig m
     )
  => UTCTime
  -> Provider
  -> m Provider
refreshProvider time =
  refreshProviderCacheIfNeeded http time >=> \case
    Right p -> pure p
    Left  u -> transaction $ do
      Just p <- listToMaybe <$> update u
      pure p

----------------------------------------------------------------------------
-- | Find the stored cookie in the database and from that get the
-- provider record too.
findSessionCookie
  :: ( Has Database      sig m
     , Has Crypto        sig m
     , Has (Throw Sterr) sig m
     )
  => SiteId
  -> ByteString
  -> m (OidcCookie, Provider)
findSessionCookie sid cookie = do
  query <- lookupProviderFromOidcCookie sid cookie
  whenNothingM (runQuery (select1 query)) $
    throwUserError MustAuthenticateError
