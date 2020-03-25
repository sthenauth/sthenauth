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
  ( getSitePublicKeys
  , getSiteCapabilities
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Crypto.JOSE.JWK as JOSE
import Iolaus.Database.Query
import qualified Opaleye as O
import Sthenauth.Core.Capabilities
import Sthenauth.Core.Config (Config)
import Sthenauth.Core.CurrentUser (CurrentUser)
import Sthenauth.Core.Error
import Sthenauth.Core.JWK (getJWK)
import Sthenauth.Core.Remote
import Sthenauth.Core.Site as Site
import Sthenauth.Core.URL
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Providers.OIDC.Public as OIDC

--------------------------------------------------------------------------------
-- | Fetch all active public keys for the given site and wrap them
-- into a key set.
getSitePublicKeys
  :: forall m sig.
     ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => SiteId
  -> m JOSE.JWKSet
getSitePublicKeys sid = do
    jwks <- runQuery (select query) >>= mapM prepKey
    pure (JOSE.JWKSet $ catMaybes jwks)

  where
    query :: O.Select (SiteKeyF SqlRead)
    query = proc () -> findActiveKeys -< sid

    prepKey :: SiteKey -> m (Maybe JOSE.JWK)
    prepKey k = (^. JOSE.asPublicKey) . getJWK <$>
      decrypt (keyData k)

--------------------------------------------------------------------------------
-- | Get the capabilities for a site.
getSiteCapabilities
  :: ( Has Database            sig m
     , Has Error               sig m
     , Has (State CurrentUser) sig m
     )
  => Config
  -> Site
  -> Remote
  -> m Capabilities
getSiteCapabilities config site remote =
  toCapabilities config (sitePolicy site)
    <$> oidcProviders
    <*> get
  where
    -- | Fix any URLs that contain @localhost@.
    oidcProviders = over mapped
      (localhostTo (remote ^. requestFqdn))
        <$> OIDC.publicProviders
