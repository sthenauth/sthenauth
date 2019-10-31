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
module Sthenauth.Core.Info
  ( getSitePrivateKeys
  ) where


--------------------------------------------------------------------------------
-- Library Imports:
import qualified Crypto.JOSE.JWK as JOSE
import qualified Iolaus.Database as DB
import qualified Iolaus.Crypto as Crypto
import qualified Opaleye as O

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Site.Key as SiteKey
import Sthenauth.Tables.Util (Id, View)
import Sthenauth.Types.JWK (getJWK)
import Sthenauth.Types.Secrets as Secrets

--------------------------------------------------------------------------------
-- | Fetch all active public keys for the given site and wrap them
-- into a key set.
getSitePrivateKeys
  :: forall m r.
     ( MonadDB m
     , MonadCrypto m
     , MonadReader r m
     , HasSecrets r
     )
  => SiteId
  -> m JOSE.JWKSet
getSitePrivateKeys sid = do
    skey <- view (secrets.symmetricKey)
    jwks <- DB.liftQuery (DB.select query) >>= mapM (prepKey skey)
    pure (JOSE.JWKSet $ catMaybes jwks)

  where
    query :: O.Select (SiteKey.Key View)
    query = proc () -> SiteKey.findActiveKeys -< sid

    prepKey :: Secrets.Key -> SiteKey.Key Id -> m (Maybe JOSE.JWK)
    prepKey skey k =
      (^. JOSE.asPublicKey) . getJWK <$>
        Crypto.decrypt skey (SiteKey.key_data k)
