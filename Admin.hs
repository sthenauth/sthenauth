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
import Iolaus.Crypto (encrypt)
import Iolaus.Database
import Iolaus.Validation (runValidationEither)
import Opaleye (Insert(..), rReturning, rCount, (.==), (.||))
import qualified Opaleye as O
import qualified Data.UUID as UUID
import Opaleye.ToFields (toFields)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Site.Alias as SiteAlias
import Sthenauth.Tables.Site.Key as SiteKey
import Sthenauth.Tables.Util
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Try to insert a new site into the database.
insertSite
  :: (MonadDB m)
  => Site Write
  -> Bool -- ^ Is the new site the default site?
  -> (SiteId -> SiteKey.Key Write)
  -> m (Maybe SiteId)
insertSite site def keyf = transaction $ do
    when def Site.resetDefaultSite
    sid <- listToMaybe <$> insert inS
    mapM_ (insert . inK) sid
    pure sid

  where
    inS = Insert sites [site] (rReturning Site.pk) Nothing
    inK sid = Insert SiteKey.keys [keyf sid] rCount Nothing

--------------------------------------------------------------------------------
-- | Validate a new site, then insert it into the database.
createSite
  :: ( MonadCrypto m
     , MonadDB m
     , MonadError e m
     , AsError e
     , AsUserError e
     )
   => UTCTime
   -> Secrets
   -> Site UI
   -> m SiteId
createSite time sec s = do
  site <- runValidationEither checkSite s >>=
            either (throwing _ValidationError) pure

  let expireIn = addSeconds (defaultPolicy ^. jwk_expires_in) time
      cryptoKey = sec ^. symmetricKey

  (jwk, keyid) <- newJWK Sig
  ejwk <- encrypt cryptoKey jwk

  let key sid = SiteKey.Key
        { pk = Nothing
        , created_at = Nothing
        , updated_at = Nothing
        , site_id = toFields sid
        , kid = toFields keyid
        , key_use = toFields Sig
        , key_data = toFields ejwk
        , expires_at = toFields expireIn
        }

  insertSite site (fromMaybe False $ is_default s) key >>=
    maybe (throwing _RuntimeError "failed to insert new site") pure

--------------------------------------------------------------------------------
-- | Locate the active site.
siteFromFQDN
  :: ( MonadDB m
     )
  => Text
  -> m (Maybe (Site Id))
siteFromFQDN fqdn =
  listToMaybe <$> liftQuery
    (select $ O.orderBy (O.asc is_default) $ O.limit 1 query)

  where
    -- Select sites where...
    query :: O.Select (Site View)
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
          defaultMatch = Site.is_default t1

      O.restrict -< (siteMatch .|| uuidMatch .|| aliasMatch .|| defaultMatch)
      returnA -< t1

    -- Join the site and site_aliases tables.
    aliasJoin :: O.SelectArr (Site View) (O.FieldNullable SqlUuid, O.FieldNullable SqlText)
    aliasJoin = proc t1 -> O.leftJoinA aliasSelect -<
      (\(uuid, _) -> uuid .== Site.pk t1)

    -- A subset of the site_aliases table.
    aliasSelect :: O.Select (O.Column SqlUuid, O.Column SqlText)
    aliasSelect = proc () -> do
      t <- O.selectTable SiteAlias.aliases -< ()
      returnA -< (SiteAlias.site_id t, SiteAlias.fqdn t)
