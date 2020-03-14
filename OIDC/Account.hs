{-# LANGUAGE Arrows #-}

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

Link accounts and providers.

-}
module Sthenauth.Providers.OIDC.Account
  ( OidcAccountF(..)
  , OidcAccount
  , ForeignAccountId
  , fromOidcAccounts
  , newOidcAccount
  , selectProviderAccountBySubject
  , selectProviderAccountByClaims
  , selectAccountsByClaims
  , updateAccountFromToken
  , extractEmailAddressFromClaims
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Crypto.JWT (NumericDate(..), ClaimsSet)
import qualified Crypto.JWT as JWT
import qualified Data.Aeson as Aeson
import Data.Aeson.Lens (_String, _Bool)
import Data.HashMap.Strict as Hash
import Data.Time.Clock
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import OpenID.Connect.TokenResponse (TokenResponse)
import qualified OpenID.Connect.TokenResponse as TR
import Sthenauth.Core.Account
import Sthenauth.Core.Email
import Sthenauth.Core.Site (SiteId)
import Sthenauth.Crypto.Effect
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Providers.OIDC.Token

--------------------------------------------------------------------------------
-- | Identifier for remote provider account IDs.
type ForeignAccountId = Text

--------------------------------------------------------------------------------
data OidcAccountF f = OidcAccount
  { oidcAccountId :: Col f "account_id" AccountId SqlUuid ForeignKey
    -- ^ Key into the accounts table.

  , accountProviderId :: Col f "provider_id" ProviderId SqlUuid ForeignKey
    -- ^ The provider who owns this account.

  , foreignAccountId :: Col f "foreign_id" Text SqlText Required
    -- ^ The internal ID used by the provider.

  , oauthAccessToken :: Col f "access_token" (Secret Text) SqlJsonb Required
    -- ^ The access token that was issued.

  , oauthRefreshToken :: Col f "refresh_token" (Secret Text) SqlJsonb Nullable
    -- ^ Optional refresh token to get a new access token.

  , oauthTokenType :: Col f "token_type" Text SqlText Required
    -- ^ How to send the access token back to the provider.  Usually "Bearer".

  , identityToken :: Col f "id_token" (Secret BinaryClaimsSet) SqlJsonb Required
    -- ^ The claim set issued by the provider.

  , oauthAccessExpiresAt :: Col f "access_expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time the access token will expire and no longer be valid.

  , oidcExpiresAt :: Col f "id_expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time the id token will expire and no longer be valid.

  , oidcAccountCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , oidcAccountUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was updated.
  }

makeTable ''OidcAccountF "accounts_openidconnect"

--------------------------------------------------------------------------------
type OidcAccount = OidcAccountF ForHask

--------------------------------------------------------------------------------
fromOidcAccounts :: Select (OidcAccountF SqlRead)
fromOidcAccounts = selectTable accounts_openidconnect

--------------------------------------------------------------------------------
-- | Create a new OIDC account record via an insert statement.
--
-- Returns two possible functions, both need an account ID in order to
-- return an insert statement.  The first insert statement is to
-- create the OIDC account.  The second is to create an email address
-- from the claim set.
--
-- If the given claim set does not have a subject this function will
-- return Nothing for both slots.  If the first slot is Nothing the
-- second slot will always be Nothing.
newOidcAccount
  :: forall sig m. Has Crypto sig m
  => SiteId                     -- ^ The current site ID.
  -> ProviderId                 -- ^ The provider this account belongs to.
  -> UTCTime                    -- ^ The current time.
  -> TokenResponse ClaimsSet    -- ^ The response from the token end-point.
  -> m ( Maybe (AccountId -> Insert Int64)
       , Maybe (AccountId -> Insert Int64)
       ) -- ^ Insert statements.
newOidcAccount sid pid time token =
  case claimsToForeignAccountId (TR.idToken token) of
    Nothing  -> pure (Nothing, Nothing)
    Just sub -> do
      acctf <- fromTokenAndSubject pid time token sub
      emailf <- emailInsertFromClaims sid (TR.idToken token)
      pure (Just (toInsert . acctf), emailf)
  where
    toInsert :: OidcAccountF SqlWrite -> Insert Int64
    toInsert a = Insert accounts_openidconnect [a] rCount Nothing

--------------------------------------------------------------------------------
-- | Create an account from a token and extracted subject.
fromTokenAndSubject
  :: Has Crypto sig m
  => ProviderId                 -- ^ The provider this account belongs to.
  -> UTCTime                    -- ^ The current time.
  -> TokenResponse ClaimsSet    -- ^ The response from the token end-point.
  -> ForeignAccountId           -- ^ The subject extracted from the claim set.
  -> m (AccountId -> OidcAccountF SqlWrite)
fromTokenAndSubject pid time token sub = do
  let aexp = addUTCTime (fromIntegral (fromMaybe 3600 (TR.expiresIn token))) time
      iexp = maybe aexp coerce (TR.idToken token ^. JWT.claimExp)
  accesst <- encrypt (TR.accessToken token)
  refresht <- traverse encrypt (TR.refreshToken token)
  idt <- encrypt (BinaryClaimsSet (TR.idToken token))
  pure $ \aid ->
    OidcAccount
      { oidcAccountId        = toFields aid
      , accountProviderId    = toFields pid
      , foreignAccountId     = toFields sub
      , oauthAccessToken     = toFields accesst
      , oauthRefreshToken    = toFields refresht
      , oauthTokenType       = toFields (TR.tokenType token)
      , identityToken        = toFields idt
      , oauthAccessExpiresAt = toFields aexp
      , oidcExpiresAt        = toFields iexp
      , oidcAccountCreatedAt = Nothing
      , oidcAccountUpdatedAt = Nothing
      }

--------------------------------------------------------------------------------
-- | A @WHERE@ clause using the primary key.
accountsPrimaryKey
  :: ProviderId
  -> ForeignAccountId
  -> OidcAccountF SqlRead
  -> O.Field O.SqlBool
accountsPrimaryKey pid aid acct =
  foreignAccountId acct  .== toFields aid .&&
  accountProviderId acct .== toFields pid

--------------------------------------------------------------------------------
-- | Update stored token information in the given account.
updateAccountFromToken
  :: Has Crypto sig m
  => OidcAccount             -- ^ The account to update.
  -> SiteId                  -- ^ Current site ID.
  -> UTCTime                 -- ^ The current time.
  -> TokenResponse ClaimsSet -- ^ The response from the token end-point.
  -> m (Update Int64, Maybe (Insert Int64))
updateAccountFromToken acct sid time token = do
    let pid = accountProviderId acct
        sub = foreignAccountId acct
    new <- fromTokenAndSubject pid time token sub
    email <- emailInsertFromClaims sid (TR.idToken token)
    pure ( toUpdate . keepOptionalColumns $ new (oidcAccountId acct)
         , email <*> pure (oidcAccountId acct)
         )
  where
    keepOptionalColumns :: OidcAccountF SqlWrite -> OidcAccountF SqlWrite
    keepOptionalColumns new = new
      { oidcAccountCreatedAt = toFields (Just (oidcAccountCreatedAt acct))
      , oidcAccountUpdatedAt = toFields (Just (oidcAccountUpdatedAt acct))
      }

    toUpdate :: OidcAccountF SqlWrite -> Update Int64
    toUpdate x =
      Update
        { uTable = accounts_openidconnect
        , uUpdateWith = const x
        , uWhere = accountsPrimaryKey
            (accountProviderId acct) (foreignAccountId acct)
        , uReturning = rCount
        }

--------------------------------------------------------------------------------
-- | Extract the subject ID from the claim set if one exists.
claimsToForeignAccountId :: ClaimsSet -> Maybe Text
claimsToForeignAccountId = fmap (view (re JWT.stringOrUri)) .  view JWT.claimSub

--------------------------------------------------------------------------------
-- | If you know the 'ForeignAccountId' for an account, this function
-- will generate a select statement to find it.
selectProviderAccountBySubject
  :: ProviderId
  -> ForeignAccountId
  -> Select (OidcAccountF SqlRead)
selectProviderAccountBySubject pid aid = proc () -> do
  t <- fromOidcAccounts -< ()
  O.restrict -< accountsPrimaryKey pid aid t
  returnA -< t

--------------------------------------------------------------------------------
-- | Find an account given by the subject of a claims set.
selectProviderAccountByClaims
  :: ProviderId
  -> ClaimsSet
  -> Maybe (Select (OidcAccountF SqlRead))
selectProviderAccountByClaims pid claims = do
  sub <- claimsToForeignAccountId claims
  pure (selectProviderAccountBySubject pid sub)

--------------------------------------------------------------------------------
-- | A query that can find an end-users OIDC account and main
-- Sthenauth account.
selectAccountsByClaims
  :: ProviderId
  -> ClaimsSet
  -> Maybe (Select (AccountF SqlRead, OidcAccountF SqlRead))
selectAccountsByClaims pid claims =
    selectProviderAccountByClaims pid claims <&> query
  where
    query
      :: Select (OidcAccountF SqlRead)
      -> Select (AccountF SqlRead, OidcAccountF SqlRead)
    query oidcAccounts = proc () -> do
      t0 <- oidcAccounts -< ()
      t1 <- fromAccounts -< ()
      O.restrict -< (oidcAccountId t0 .== accountId t1)
      returnA -< (t1, t0)

--------------------------------------------------------------------------------
-- | Return an email insert statement if an email can be extracted
-- from the claim set.
emailInsertFromClaims
  :: Has Crypto sig m
  => SiteId
  -> ClaimsSet
  -> m (Maybe (AccountId -> Insert Int64))
emailInsertFromClaims sid claims =
  traverse (\(e,v) -> (,v) <$> toSafeEmail e)
    (extractEmailAddressFromClaims claims) >>= \case
      Nothing -> pure Nothing
      Just (se, ev) -> pure . Just $ \aid ->
        newAccountEmail se sid (bool Nothing claimTime ev) aid
  where
    claimTime :: Maybe UTCTime
    claimTime = claims ^. JWT.claimIat <&> coerce

--------------------------------------------------------------------------------
-- | Extract an email address and the @email_verified@ flag from a
-- provider's claim set.
extractEmailAddressFromClaims :: ClaimsSet -> Maybe (Email, Bool)
extractEmailAddressFromClaims claims = do
    ea <- claimAtKey "email" >>= (^? _String) >>= toEmail
    ev <- (claimAtKey "email_verified" >>= (^? _Bool)) <|> Just False
    pure (ea, ev)
  where
     claimAtKey :: Text -> Maybe Aeson.Value
     claimAtKey key = Hash.lookup key (claims ^. JWT.unregisteredClaims)
