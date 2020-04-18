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
  , newSite
  , insertSitesReturningId
  , insertSitesReturningCount
  , updateSite
  , modifyPolicy
  , siteFromFQDN
  , defaultSite
  , createInitialSite
  , createInitialSiteIfMissing
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Control.Lens ((^.), lens)
import Data.Time.Clock (UTCTime)
import qualified Data.UUID as UUID
import Iolaus.Database.Extra
import Iolaus.Database.Query hiding ((.?))
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Policy
import Sthenauth.Core.URL

--------------------------------------------------------------------------------
type SiteId = Key UUID SiteF

--------------------------------------------------------------------------------
-- | The accounts table in the database.
data SiteF f = Site
  { siteId :: Col f "id" SiteId SqlUuid ReadOnly
    -- ^ Primary key.

  , siteIsDefault :: Col f "is_default" Bool SqlBool Required
    -- ^ Is this site the default site?

  , siteAfterLoginUrl :: Col f "after_login_url" URL SqlText Required
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

makeTable ''SiteF "sites"

--------------------------------------------------------------------------------
-- | Monomorphic site.
type Site = SiteF ForHask

--------------------------------------------------------------------------------
instance HasURL Site where
  url = lens getter setter
    where
      getter :: Site -> URL
      getter = urlFromFQDN . siteFqdn

      setter :: Site -> URL -> Site
      setter s u = s { siteFqdn = u ^. urlDomain }

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

  }

makeTable ''SiteAliasF "site_aliases"

--------------------------------------------------------------------------------
-- | Monomorphic 'AliasF' type.
type SiteAlias = SiteAliasF ForHask

--------------------------------------------------------------------------------
newtype NewSites = NewSites
   [( Bool           -- Is this site the new default?
    , SiteF SqlWrite -- The site.
    )
   ]

instance Semigroup NewSites where
  (<>) (NewSites x) (NewSites y) = NewSites (x <> y)

--------------------------------------------------------------------------------
newSite :: Text -> Bool -> NewSites
newSite fqdn isDefault = NewSites [(isDefault, site)]
  where
    site :: SiteF SqlWrite
    site =
      Site
        { siteId = Nothing
        , siteIsDefault = toFields isDefault
        , siteAfterLoginUrl = toFields (urlFromFQDN fqdn)
        , siteFqdn = toFields fqdn
        , sitePolicy = toFields defaultPolicy
        , siteCreatedAt = Nothing
        , siteUpdatedAt = Nothing
        }

--------------------------------------------------------------------------------
insertSites' :: NewSites -> (Maybe (Update Int64), [SiteF SqlWrite])
insertSites' (NewSites s) = (maybeUpdate, firstDefault)
  where
    maybeUpdate :: Maybe (Update Int64)
    maybeUpdate = if any fst s then Just resetDefaultSite else Nothing

    -- Only let one site be the new default.
    firstDefault :: [SiteF SqlWrite]
    firstDefault = snd $ foldl' changeDefault (True, []) s

    -- Check each site to see if it's allowed to be the default.
    changeDefault
      :: (Bool, [SiteF SqlWrite])
      -> (Bool,  SiteF SqlWrite)
      -> (Bool, [SiteF SqlWrite])
    changeDefault (defaultAllowed, ls) (isDefault, site) =
      if defaultAllowed && isDefault
        then (False,          (site {siteIsDefault=toFields True}):ls)
        else (defaultAllowed, (site {siteIsDefault=toFields False}):ls)

--------------------------------------------------------------------------------
-- | You must run this in a transaction!
insertSitesReturningId :: NewSites -> Query [Site]
insertSitesReturningId n = do
  let (u, ss) = insertSites' n
  traverse_ update u
  insert (Insert sites ss (rReturning id) Nothing)

--------------------------------------------------------------------------------
-- | You must run this in a transaction!
insertSitesReturningCount :: NewSites -> Query Int64
insertSitesReturningCount n = do
  let (u, ss) = insertSites' n
  traverse_ update u
  insert (Insert sites ss rCount Nothing)

--------------------------------------------------------------------------------
-- | Locate a site using it's FQDN (or alias).  If the site can't be
-- found the default site will be returned instead.
siteFromFQDN :: Text -> Select (SiteF SqlRead)
siteFromFQDN fqdn = query where
  -- Select sites where...
  query :: O.Select (SiteF SqlRead)
  query = proc () -> do
    t1 <- selectTable sites -< ()
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
    t <- selectTable site_aliases -< ()
    returnA -< (aliasSiteId t, aliasFqdn t)

--------------------------------------------------------------------------------
updateSite :: Site -> Query Int64
updateSite site = do
  when (siteIsDefault site) (void $ update resetDefaultSite)
  update $ Update
    { uTable = sites
    , uWhere = \t -> siteId t .== toFields (siteId site)
    , uReturning = rCount
    , uUpdateWith = O.updateEasy $ \s ->
        s { siteIsDefault = toFields (siteIsDefault site)
          , siteAfterLoginUrl = toFields (siteAfterLoginUrl site)
          , siteFqdn = toFields (siteFqdn site)
          }
    }

--------------------------------------------------------------------------------
-- | A query that updates a policy using the supplied function.
modifyPolicy :: Site -> (Policy -> Policy) -> Update Int64
modifyPolicy site f =
  Update
    { uTable = sites
    , uUpdateWith = O.updateEasy (\s -> s { sitePolicy = toFields (f (sitePolicy site))})
    , uWhere = \t -> siteId t .== toFields (siteId site)
    , uReturning = O.rCount
    }

--------------------------------------------------------------------------------
-- | Remove the @is_default@ flag from all existing sites.
--
-- This is needed when creating a new site and it was flagged as the
-- default site, or when updating an existing site and setting it to be
-- the new default.
resetDefaultSite :: Update Int64
resetDefaultSite =
  Update
    { uTable = sites
    , uUpdateWith = O.updateEasy (\s -> s {siteIsDefault = toFields False})
    , uWhere = siteIsDefault
    , uReturning = O.rCount
    }

--------------------------------------------------------------------------------
-- | Select the default site or fail.
defaultSite :: Query Site
defaultSite = do
    Just s <- select1 query
    pure s
  where
    query :: Select (SiteF SqlRead)
    query = proc () -> do
      t <- selectTable sites -< ()
      O.restrict -< siteIsDefault t
      returnA -< t

--------------------------------------------------------------------------------
defaultSiteFqdn :: Text
defaultSiteFqdn = "localhost"

--------------------------------------------------------------------------------
-- | Create the initial site.
--
-- @since 0.1.0.0
createInitialSite :: Query Site
createInitialSite = do
  Just site <- insertSitesReturningId (newSite defaultSiteFqdn True) <&> listToMaybe
  pure site

--------------------------------------------------------------------------------
-- | Create the initial site if it doesn't exist.
--
-- @since 0.1.0.0
createInitialSiteIfMissing :: Query ()
createInitialSiteIfMissing = do
    n <- count query
    when (n == 0) (void createInitialSite)

  where
    query :: Select (SiteF SqlRead)
    query = proc () -> do
      t <- selectTable sites -< ()
      O.restrict -< (siteIsDefault t .|| siteFqdn t .== toFields defaultSiteFqdn)
      returnA -< t
