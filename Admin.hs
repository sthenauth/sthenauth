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
import Iolaus.Opaleye
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
import Sthenauth.Types.Remote
import Sthenauth.Types.Secrets

--------------------------------------------------------------------------------
-- | Try to insert a new site into the database.
insertSite
  :: (MonadOpaleye m)
  => Site Write
  -> (SiteId -> SiteKey.Key Write)
  -> m (Maybe SiteId)
insertSite site keyf = transaction $ do
    sid <- listToMaybe <$> insert inS
    mapM_ (insert . inK) sid
    pure sid

  where
    inS = Insert sites [site] (rReturning Site.pk) Nothing
    inK sid = Insert SiteKey.keys [keyf sid] rCount Nothing

--------------------------------------------------------------------------------
createSite
  :: ( MonadCrypto m
     , MonadOpaleye m
     , MonadRandom m
     , MonadError e m
     , MonadReader r m
     , AsError e
     , AsUserError e
     , HasSecrets r c
     , HasRemote r
     , BlockCipher c
     )
   => Site UI
   -> m SiteId
createSite s = do
  site <- runValidationEither checkSite s >>=
            either (throwing _ValidationError) pure

  rtime <- request_time <$> view remote
  let expireIn = nominalSeconds (jwkExpiresIn defaultPolicy)

  cryptoKey <- view (secrets.symmetricKey)
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
        , expires_at = toFields (addUTCTime expireIn rtime)
        }

  insertSite site key >>=
    maybe (throwing _RuntimeError "failed to insert new site") pure
