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
module Sthenauth.Providers.OIDC.Flow
  ( AccessCode
  , Request(..)
  , Response(..)
  , step
  ) where

--------------------------------------------------------------------------------
import Iolaus.Database.Query
import Network.URI (URI)
import qualified Opaleye as O
import Sthenauth.Core.Account
import Sthenauth.Core.Error
import Sthenauth.Core.PostLogin
import Sthenauth.Core.Remote
import Sthenauth.Core.Session (Session, ClearSessionKey, newSessionKey)
import Sthenauth.Core.Site (Site, sitePolicy)
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Providers.OIDC.Account
import Sthenauth.Providers.OIDC.Effect
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Providers.OIDC.Session

--------------------------------------------------------------------------------
type AccessCode = Text

--------------------------------------------------------------------------------
data Request
  = Init Site ProviderId
  | Callback Site ClearSessionKey AccessCode

--------------------------------------------------------------------------------
data Response
  = RedirectTo URI
  | Success (Session, ClearSessionKey, PostLogin)
  | Failed

--------------------------------------------------------------------------------
type Deps sig m =
  ( Has Crypto   sig m
  , Has Database sig m
  , Has OIDC     sig m
  , Has Error    sig m
  )

--------------------------------------------------------------------------------
step
  :: Deps sig m
  => Remote
  -> Request
  -> m Response
step remote = \case
  Init site provider -> initOIDC site remote provider
  Callback site stateKey accessCode -> verifyOIDC site remote stateKey accessCode

--------------------------------------------------------------------------------
initOIDC
  :: Deps sig m
  => Site
  -> Remote
  -> ProviderId
  -> m Response
initOIDC site remote pid =
  runQuery (select1 (providerById pid)) >>= \case
    Nothing -> pure Failed
    Just provider -> do
      details <- providerDiscovery site provider
      (key, newPartial) <- newPartialSession remote site (providerId provider)
      partial <- runQuery (insertPartialReturningId newPartial)
      RedirectTo <$> getRedirectUrl key partial details

--------------------------------------------------------------------------------
verifyOIDC
  :: Deps sig m
  => Site
  -> Remote
  -> ClearSessionKey
  -> AccessCode
  -> m Response
verifyOIDC site remote key code = do
  query <- partialSessionQuery key
  runQuery (select1 query) >>= \case
    Nothing -> pure Failed
    Just (partial, provider) -> do
      details <- providerDiscovery site provider
      token <- getEmailToken partial details
      Success <$> createCompleteOidcSession site remote partial provider token

--------------------------------------------------------------------------------
createCompleteOidcSession
  :: Deps sig m
  => Site
  -> Remote
  -> Partial
  -> Provider
  -> EmailToken
  -> m (Session, ClearSessionKey, PostLogin)
createCompleteOidcSession site remote partial Provider{providerId} token = do
    (clear, key) <- newSessionKey

    session <- transaction $ do
        let foreignId = tokenSubject token
        acct <- select1 (selectProviderAccount providerId foreignId) >>= \case
          Just a -> pure (oidcAccountId a)
          Nothing -> createNewAccounts foreignId

        let newsess = newSession acct remote (sitePolicy site) key
            maxsess = sitePolicy site ^. maxSessionsPerAccount
        Just session <- insertSession maxsess newsess

    pure (session, clear, undefined)

  where
    createNewAccounts :: ForeignAccountId -> Query AccountId
    createNewAccounts fid = do
      acct <- flip createAccount (const []) $ Account
        { accountId = Nothing
        , accountSiteId = toFields (partialSiteId partial)
        , accountUsername = O.null
        , accountPassword = O.null
        , accountCreatedAt = Nothing
        , accountUpdatedAt = Nothing
        }
      insertOidcAccountReturningNothing $ OidcAccount
        { oidcAccountId = toFields (accountId acct)
        , accountProviderId = toFields providerId
        , foreignAccountId = toFields fid
        , oidcAccountCreatedAt = Nothing
        }
      pure (accountId acct)
