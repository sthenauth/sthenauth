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

-}
module Sthenauth.Core.Site
  ( SiteF(..)
  , Site
  , SiteId
  , SiteAliasF(..)
  , SiteAlias
  , SiteAliasId
  , SiteKeyF(..)
  , SiteKey
  , SiteKeyId
  , createSite
  , findKeys
  , findActiveKeys
  , siteFromFQDN
  , doesSiteExist
  , modifyPolicy
  , defaultSite
  , resetDefaultSite
  , checkSite
  , validateSite
  , siteForUI
  , siteURI
  , oidcCallbackURI
  , postLogin
  , insertSite
  , updateSite
  , insertAlias
  , sessionCookieName
  , oidcCookieName
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Data.Time.Clock (UTCTime)
import qualified Data.UUID as UUID
import Iolaus.Database.Extra
import Iolaus.Database.Query hiding ((.?))
import Iolaus.Database.Table
import Iolaus.Validation
import qualified Opaleye as O
import Sthenauth.Core.Error
import Sthenauth.Core.JWK
import Sthenauth.Core.Policy
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Core.PostLogin
import Text.URI (URI)
import qualified Text.URI as URI
import Text.URI.Lens

--------------------------------------------------------------------------------
type SiteId = Key UUID SiteF

--------------------------------------------------------------------------------
-- | The accounts table in the database.
data SiteF f = Site
  { siteId :: Col f "id" SiteId SqlUuid ReadOnly
    -- ^ Primary key.

  , siteIsDefault :: Col f "is_default" Bool SqlBool Optional
    -- ^ Is this site the default site?

  , afterLoginUrl :: Col f "after_login_url" Text SqlText Optional
    -- ^ Where to send users after logging in.

  , siteFqdn :: Col f "fqdn" Text SqlText Required
    -- ^ The FQDN for this site.

  , sitePolicy :: Col f "policy" Policy SqlJsonb Required
    -- ^ The site's security policy.

  , siteCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , siteUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was last updated.

  }
  deriving Generic

deriving via (GenericJSON (SiteF ForUI)) instance ToJSON   (SiteF ForUI)
deriving via (GenericJSON (SiteF ForUI)) instance FromJSON (SiteF ForUI)

makeTable ''SiteF "sites"

--------------------------------------------------------------------------------
-- | Monomorphic site.
type Site = SiteF ForHask

--------------------------------------------------------------------------------
-- | Primary key on the @site_aliases@ table.
type SiteAliasId = Key UUID SiteAliasF

--------------------------------------------------------------------------------
-- | The accounts table in the database.
data SiteAliasF f = SiteAlias
  { aliasId :: Col f "id" SiteAliasId SqlUuid ReadOnly
    -- ^ Primary key.

  , aliasSiteId :: Col f "site_id" SiteId SqlUuid ForeignKey
    -- ^ The site this alias belongs to.

  , aliasFqdn :: Col f "fqdn" Text SqlText Required
    -- ^ The FQDN for this alias.

  , aliasCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , aliasUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was last updated.

  } deriving Generic

deriving via (GenericJSON (SiteAliasF ForUI)) instance ToJSON   (SiteAliasF ForUI)
deriving via (GenericJSON (SiteAliasF ForUI)) instance FromJSON (SiteAliasF ForUI)
makeTable ''SiteAliasF "site_aliases"

--------------------------------------------------------------------------------
-- | Monomorphic 'AliasF' type.
type SiteAlias = SiteAliasF ForHask

--------------------------------------------------------------------------------
-- | Primary key on the @site_keys@ table.
type SiteKeyId = Key UUID SiteKeyF

--------------------------------------------------------------------------------
data SiteKeyF f = SiteKey
  { keyId :: Col f "id" SiteKeyId SqlUuid ReadOnly
    -- ^ Primary key.

  , keySiteId :: Col f "site_id" SiteId SqlUuid ForeignKey
    -- ^ The site this key is for.

  , jwkId :: Col f "kid" Text SqlText Required
    -- ^ The key's internal ID.

  , keyUse :: Col f "key_use" KeyUse SqlKeyUse Required
    -- ^ What this key can be used for.

  , keyData :: Col f "key_data" (Secret JWK) SqlJsonb Required
    -- ^ The encrypted key data.

  , keyCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , keyUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was last updated.

  , keyExpiresAt :: Col f "expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time this record will expire.

  } deriving Generic

deriving via (GenericJSON (SiteKeyF ForUI)) instance ToJSON   (SiteKeyF ForUI)
deriving via (GenericJSON (SiteKeyF ForUI)) instance FromJSON (SiteKeyF ForUI)
makeTable ''SiteKeyF "site_keys"

--------------------------------------------------------------------------------
-- | Monomorphic key.
type SiteKey = SiteKeyF ForHask

--------------------------------------------------------------------------------
-- | Find all keys for the given site.
findKeys :: SelectArr SiteId (SiteKeyF SqlRead)
findKeys = proc sid -> do
  t <- O.selectTable site_keys -< ()
  O.restrict -< keySiteId t .== toFields sid
  returnA -< t

--------------------------------------------------------------------------------
-- | Find all keys for the given site that are not expired.
findActiveKeys :: SelectArr SiteId (SiteKeyF SqlRead)
findActiveKeys = proc sid -> do
  t <- findKeys -< sid
  O.restrict -< keyExpiresAt t .> transactionTimestamp
  returnA -< t
--------------------------------------------------------------------------------
-- | Try to insert a single account into the database.
insertAlias :: SiteAliasF SqlWrite -> Query (Maybe SiteAliasId)
insertAlias = insert1 . ins
  where
    ins :: SiteAliasF SqlWrite -> Insert [SiteAliasId]
    ins a = Insert site_aliases [a] (rReturning aliasId) Nothing

--------------------------------------------------------------------------------
-- | Validate a new site, then insert it into the database.
createSite
  :: forall m sig.
     ( MonadRandom      m
     , Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
   => UTCTime
   -> SiteF ForUI
   -> m SiteId
createSite time s = do
    site <- validateSite s
    key <- mkKey
    insertSite site (fromMaybe False $ siteIsDefault s) (onInsert key) >>=
      maybe (throwError (RuntimeError "failed to insert new site")) pure
  where
    -- Code to run after a Site is inserted into the database.
    onInsert
      :: (SiteId -> SiteKeyF SqlWrite)
      -> Site
      -> Query SiteId
    onInsert key site = do
      1 <- insert (Insert site_keys [key (siteId site)] rCount Nothing)
      pure (siteId site)

    -- Create a function that when given a SiteId, returns a site key.
    mkKey :: m (SiteId -> SiteKeyF SqlWrite)
    mkKey = do
      let expireIn = addSeconds (defaultPolicy ^. jwkExpiresIn) time
      (jwk, keyid) <- newJWK Sig
      ejwk <- encrypt jwk
      pure $ \sid ->
        SiteKey
          { keyId        = Nothing
          , keyCreatedAt = Nothing
          , keyUpdatedAt = Nothing
          , keySiteId    = toFields sid
          , jwkId        = toFields keyid
          , keyUse       = toFields Sig
          , keyData      = toFields ejwk
          , keyExpiresAt = toFields expireIn
          }

--------------------------------------------------------------------------------
-- | Locate a site using it's FQDN (or alias).  If the site can't be
-- found the default site will be returned instead.
--
-- This query intentionally uses an incomplete pattern so that if the
-- query fails to produce a site an error will be thrown.
siteFromFQDN :: (Has Database sig m, Has Error sig m) => Text -> m Site
siteFromFQDN fqdn = runQuery $ do
    Just site <- select1 $ O.orderBy (O.asc siteIsDefault) query
    pure site
  where
    -- Select sites where...
    query :: O.Select (SiteF SqlRead)
    query = proc () -> do
      t1 <- O.selectTable sites -< ()
      (_, domain) <- aliasJoin -< t1

          -- 1. Request domain matches the site's FQDN.
      let siteMatch = siteFqdn t1 `lowerEq` fqdn

          -- 2. UUID match (mostly for command line and testing).
          uuidMatch = case UUID.fromText fqdn of
                        Nothing -> toFields False
                        Just u  -> siteId t1 .== toFields u

          -- 3. Request domain matches a site alias' FQDN.
          aliasMatch = O.matchNullable (toFields False)
                       (`lowerEq` fqdn) domain

          -- 4. The site is marked as the default site.
          defaultMatch = siteIsDefault t1

      O.restrict -< (siteMatch .|| uuidMatch .|| aliasMatch .|| defaultMatch)
      returnA -< t1

    -- Join the site and site_aliases tables.
    aliasJoin :: O.SelectArr (SiteF SqlRead) (O.FieldNullable SqlUuid, O.FieldNullable SqlText)
    aliasJoin = proc t1 -> O.leftJoinA aliasSelect -<
      (\(uuid, _) -> uuid .== siteId t1)

    -- A subset of the site_aliases table.
    aliasSelect :: O.Select (O.Column SqlUuid, O.Column SqlText)
    aliasSelect = proc () -> do
      t <- O.selectTable site_aliases -< ()
      returnA -< (aliasSiteId t, aliasFqdn t)

--------------------------------------------------------------------------------
-- | Check if a 'Site' exists.
doesSiteExist :: (Has Database sig m, Has Error sig m) => Text -> m Bool
doesSiteExist domain = (/= 0) <$> runQuery (count query)
  where
    query = proc () -> do
      t <- O.selectTable sites -< ()
      O.restrict -< siteFqdn t `lowerEq` domain
      returnA -< t

--------------------------------------------------------------------------------
-- | A query that updates a policy using the supplied function.
modifyPolicy :: Site -> (Policy -> Policy) -> Query ()
modifyPolicy site f = void . update $ O.Update
  { O.uTable = sites
  , O.uUpdateWith = O.updateEasy (\s -> s { sitePolicy = toFields (f (sitePolicy site))})
  , O.uWhere = \t -> siteId t .== toFields (siteId site)
  , O.uReturning = O.rCount
  }

--------------------------------------------------------------------------------
-- | A query to return the default site.
defaultSite :: O.Select (SiteF SqlRead)
defaultSite = proc () -> do
    t <- O.selectTable sites -< ()
    O.restrict -< siteIsDefault t .== toFields True
    returnA -< t

--------------------------------------------------------------------------------
-- | Remove the @is_default@ flag from all existing sites.
--
-- This is needed when creating a new site and it was flagged as the
-- default site, or when updating an existing site and setting it to be
-- the new default.
resetDefaultSite :: Query ()
resetDefaultSite = void . update $ Update
  { uTable = sites
  , uUpdateWith = O.updateEasy (\s -> s {siteIsDefault = toFields False})
  , uWhere = siteIsDefault
  , uReturning = O.rCount
  }

--------------------------------------------------------------------------------
-- | Validate a 'Site' coming from the user interface.
checkSite
  :: (Has Database sig m, Has Error sig m)
  => ValidationT m (SiteF ForUI) (SiteF SqlWrite)
checkSite = Site
  <$> {- Not allowed in JSON -}           pure Nothing <?> "pk"
  <*> (toFields      <$> siteIsDefault .? passthru     <?> "is_default")
  <*> (toFields      <$> afterLoginUrl .? notBlank     <?> "after_login_url")
  <*> (toFields      <$> siteFqdn      .: checkFQDN    <?> "fqdn")
  <*> (sqlValueJSONB <$> sitePolicy    .: checkPolicy  <?> "policy")
  <*> {- Not allowed in JSON -}           pure Nothing <?> "created_at"
  <*> {- Not allowed in JSON -}           pure Nothing <?> "updated_at"

  where
    checkFQDN = notBlank *> assertM (Invalid "already taken")
                                    (fmap not . doesSiteExist)

--------------------------------------------------------------------------------
-- | Run the site validation checker.
validateSite
  :: (Has Database sig m, Has Error sig m)
  => SiteF ForUI -> m (SiteF SqlWrite)
validateSite =
  runValidationEither checkSite >=>
    either (throwError . ApplicationUserError . ValidationError) pure

--------------------------------------------------------------------------------
-- | Convert a site to one that can be used in the UI.
siteForUI :: Site -> SiteF ForUI
siteForUI s = Site
  { siteId        = NotAllowed ()
  , siteIsDefault = Just (siteIsDefault s)
  , afterLoginUrl = Just (afterLoginUrl s)
  , siteFqdn      = siteFqdn s
  , sitePolicy    = sitePolicy s
  , siteCreatedAt = NotAllowed ()
  , siteUpdatedAt = NotAllowed ()
  }

--------------------------------------------------------------------------------
-- | Construct a URI from a site.
siteURI :: Site -> URI
siteURI s = fromMaybe URI.emptyURI $ do
  scheme <- URI.mkScheme "https"
  host <- URI.mkHost (siteFqdn s) <|> URI.mkHost "localhost"

  return $ URI.emptyURI &
    uriScheme ?~ scheme &
    uriAuthority .~ Right (URI.Authority Nothing host Nothing)

--------------------------------------------------------------------------------
-- | The URL for OIDC providers to call back into.
--
-- FIXME: Need a way to tie this to the servant server.
oidcCallbackURI :: Site -> URI
oidcCallbackURI s = fromMaybe (siteURI s) $ do
  path <- mapM URI.mkPathPiece ["auth", "oidc", "login", "done"]
  pure (siteURI s & uriPath .~ path)

--------------------------------------------------------------------------------
-- | Create post-login instructions for the UI.
postLogin :: Site -> PostLogin
postLogin s = PostLogin alu

  where
    suri :: URI
    suri = siteURI s

    -- Parse the @after_login_url@ text, updating the scheme and host
    -- name from the site URI if they are missing.
    alu :: URI
    alu = fromMaybe suri $ do
      u <- URI.mkURI (afterLoginUrl s)

      return $ u &
        uriScheme %~ (<|> (suri ^. uriScheme)) &
        uriAuthority %~ either (const (suri ^. uriAuthority)) Right

--------------------------------------------------------------------------------
-- | Try to insert a new site into the database.
insertSite
  :: (Has Database sig m, Has Error sig m)
  => SiteF SqlWrite
  -> Bool -- ^ Is the new site the default site?
  -> (Site -> Query a)
  -> m (Maybe a)
insertSite site def f =
  transaction $ do
    when def resetDefaultSite
    insert1 inS >>= \case
      Nothing -> pure Nothing
      Just s  -> Just <$> f s
  where
    inS = Insert sites [site] (rReturning id) Nothing

--------------------------------------------------------------------------------
-- | Update (some) fields of the Site record.
updateSite
  :: (Has Database sig m, Has Error sig m)
  => SiteId -> SiteF ForUI -> m ()
updateSite sid ui = do
    site <- validateSite ui
    transaction $ do
      when (fromMaybe False (siteIsDefault ui)) resetDefaultSite
      1 <- update (mkUpdate site)
      pass
  where
    mkUpdate :: SiteF SqlWrite -> Update Int64
    mkUpdate site = Update
      { uTable = sites
      , uWhere = \s -> siteId s .== toFields sid
      , uReturning = O.rCount
      , uUpdateWith = O.updateEasy (\s ->
          s { siteFqdn          = siteFqdn site
            , afterLoginUrl = fromMaybe "/" (afterLoginUrl site)
            , siteIsDefault     = fromMaybe (toFields False) (siteIsDefault site)
            })
      }

--------------------------------------------------------------------------------
-- | FIXME: make this a site parameter.
sessionCookieName :: Site -> Text
sessionCookieName _ = "ss"

--------------------------------------------------------------------------------
-- | The name of a cookie for OIDC authentication requests.
oidcCookieName :: Site -> Text
oidcCookieName = sessionCookieName >>> (<> "_oidc")
