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
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.Time.Clock (addUTCTime)
import Iolaus.Crypto (encrypt)
import Iolaus.Database
import Iolaus.Validation (runValidationEither)
import Opaleye (Insert(..), rReturning, rCount)
import Opaleye.ToFields (toFields)

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Site.Key as SiteKey
import Sthenauth.Tables.Util
import Sthenauth.Types.Error
import Sthenauth.Types.JWK
import Sthenauth.Types.Policy
import Sthenauth.Types.Secrets

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
createSite
  :: ( MonadCrypto m
     , MonadDB m
     , MonadRandom m
     , MonadError e m
     , AsError e
     , AsUserError e
     , BlockCipher c
     )
   => UTCTime
   -> Secrets c
   -> Site UI
   -> m SiteId
createSite time sec s = do
  site <- runValidationEither checkSite s >>=
            either (throwing _ValidationError) pure

  let expireIn = nominalSeconds (jwkExpiresIn defaultPolicy)
      cryptoKey = sec ^. symmetricKey

  (jwk, keyid) <- newJWK
  ejwk <- encrypt cryptoKey jwk

  let key sid = SiteKey.Key
        { pk = Nothing
        , created_at = Nothing
        , updated_at = Nothing
        , site_id = toFields sid
        , kid = toFields keyid
        , key_use = toFields Sig
        , key_data = toFields ejwk
        , expires_at = toFields (addUTCTime expireIn time)
        }

  insertSite site (fromMaybe False $ is_default s) key >>=
    maybe (throwing _RuntimeError "failed to insert new site") pure
