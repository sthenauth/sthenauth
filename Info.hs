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
  :: forall m k r.
     ( MonadDB m
     , MonadCrypto k m
     , MonadReader r m
     , HasSecrets  r k
     )
  => SiteId
  -> m JOSE.JWKSet
getSitePrivateKeys sid = do
    jwks <- DB.liftQuery (DB.select query) >>= mapM prepKey
    pure (JOSE.JWKSet $ catMaybes jwks)

  where
    query :: O.Select (SiteKey.Key View)
    query = proc () -> SiteKey.findActiveKeys -< sid

    prepKey :: SiteKey.Key Id -> m (Maybe JOSE.JWK)
    prepKey k = (^. JOSE.asPublicKey) . getJWK <$>
      decrypt (SiteKey.key_data k)
