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
-- Imports:
import qualified Crypto.JOSE.JWK as JOSE
import Iolaus.Database.Query
import qualified Opaleye as O
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Core.Site as Site
import Sthenauth.Core.Error
import Sthenauth.Core.JWK (getJWK)

--------------------------------------------------------------------------------
-- | Fetch all active public keys for the given site and wrap them
-- into a key set.
getSitePrivateKeys
  :: forall m sig.
     ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => SiteId
  -> m JOSE.JWKSet
getSitePrivateKeys sid = do
    jwks <- runQuery (select query) >>= mapM prepKey
    pure (JOSE.JWKSet $ catMaybes jwks)

  where
    query :: O.Select (SiteKeyF SqlRead)
    query = proc () -> findActiveKeys -< sid

    prepKey :: SiteKey -> m (Maybe JOSE.JWK)
    prepKey k = (^. JOSE.asPublicKey) . getJWK <$>
      decrypt (keyData k)
