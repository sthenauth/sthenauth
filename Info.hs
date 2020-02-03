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
import Control.Monad.Database.Class
import qualified Crypto.JOSE.JWK as JOSE
import Iolaus.Database.Query
import qualified Opaleye as O

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Tables.Site as Site
import Sthenauth.Tables.Site.Key as SiteKey
import Sthenauth.Types.Error
import Sthenauth.Types.JWK (getJWK)
import Sthenauth.Types.Secrets as Secrets

--------------------------------------------------------------------------------
-- | Fetch all active public keys for the given site and wrap them
-- into a key set.
getSitePrivateKeys
  :: forall m k e r.
     ( MonadDatabase m
     , MonadCrypto k m
     , MonadError  e m
     , AsDbError     e
     , AsCryptoError e
     , MonadReader r m
     , HasSecrets  r k
     )
  => SiteId
  -> m JOSE.JWKSet
getSitePrivateKeys sid = do
    jwks <- runQuery (select query) >>= mapM prepKey
    pure (JOSE.JWKSet $ catMaybes jwks)

  where
    query :: O.Select (SiteKey.KeyF SqlRead)
    query = proc () -> SiteKey.findActiveKeys -< sid

    prepKey :: SiteKey.Key -> m (Maybe JOSE.JWK)
    prepKey k = (^. JOSE.asPublicKey) . getJWK <$>
      decrypt (SiteKey.keyData k)
