{-# LANGUAGE Arrows #-}

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
module Sthenauth.Core.Admin
  ( createSite
  , siteFromFQDN
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Arrow (returnA)
import Control.Monad.Database.Class
import qualified Data.UUID as UUID
import Iolaus.Database.Extra (lowerEq)
import Iolaus.Database.Query
import Iolaus.Validation (runValidationEither)
import qualified Opaleye as O
import Opaleye.SqlTypes

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Site.Alias as SiteAlias
import Sthenauth.Tables.Site.Key as SiteKey
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Validate a new site, then insert it into the database.
createSite
  :: forall m k e r.
     ( Database e m
     , Crypto k e m
     , MonadReader r m
     , HasSecrets  r k
     , MonadRandom   m
     , AsSystemError e
     , AsUserError e
     )
   => UTCTime
   -> SiteF ForUI
   -> m SiteId
createSite time s = do
    site <- runValidationEither checkSite s >>=
              either (throwing _ValidationError) pure
    key <- mkKey
    insertSite site (fromMaybe False $ isDefault s) (onInsert key) >>=
      maybe (throwing _RuntimeError "failed to insert new site") pure
  where
    -- Code to run after a Site is inserted into the database.
    onInsert
      :: (SiteId -> SiteKey.KeyF SqlWrite)
      -> Site
      -> Query SiteId
    onInsert key site = do
      1 <- insert (Insert SiteKey.site_keys [key (Site.pk site)] rCount Nothing)
      pure (Site.pk site)

    -- Create a function that when given a SiteId, returns a site key.
    mkKey :: m (SiteId -> SiteKey.KeyF SqlWrite)
    mkKey = do
      let expireIn = addSeconds (defaultPolicy ^. jwkExpiresIn) time
      (jwk, keyid) <- newJWK Sig
      ejwk <- encrypt jwk
      pure $ \sid ->
        SiteKey.Key
          { pk        = Nothing
          , createdAt = Nothing
          , updatedAt = Nothing
          , siteId    = toFields sid
          , kid       = toFields keyid
          , keyUse    = toFields Sig
          , keyData   = toFields ejwk
          , expiresAt = toFields expireIn
          }

--------------------------------------------------------------------------------
-- | Locate the active site.
siteFromFQDN
  :: ( MonadDatabase m
     , MonadError  e m
     , AsDbError   e
     )
  => Text
  -> m (Maybe Site)
siteFromFQDN fqdn =
    runQuery (select1 $ O.orderBy (O.asc isDefault) query)

  where
    -- Select sites where...
    query :: O.Select (SiteF SqlRead)
    query = proc () -> do
      t1 <- O.selectTable sites -< ()
      (_, domain) <- aliasJoin -< t1

          -- 1. Request domain matches the site's FQDN.
      let siteMatch = Site.fqdn t1 `lowerEq` fqdn

          -- 2. UUID match (mostly for command line and testing).
          uuidMatch = case UUID.fromText fqdn of
                        Nothing -> toFields False
                        Just u  -> Site.pk t1 .== toFields u

          -- 3. Request domain matches a site alias' FQDN.
          aliasMatch = O.matchNullable (toFields False)
                       (`lowerEq` fqdn) domain

          -- 4. The site is marked as the default site.
          defaultMatch = Site.isDefault t1

      O.restrict -< (siteMatch .|| uuidMatch .|| aliasMatch .|| defaultMatch)
      returnA -< t1

    -- Join the site and site_aliases tables.
    aliasJoin :: O.SelectArr (SiteF SqlRead) (O.FieldNullable SqlUuid, O.FieldNullable SqlText)
    aliasJoin = proc t1 -> O.leftJoinA aliasSelect -<
      (\(uuid, _) -> uuid .== Site.pk t1)

    -- A subset of the site_aliases table.
    aliasSelect :: O.Select (O.Column SqlUuid, O.Column SqlText)
    aliasSelect = proc () -> do
      t <- O.selectTable SiteAlias.site_aliases -< ()
      returnA -< (SiteAlias.siteId t, SiteAlias.fqdn t)
