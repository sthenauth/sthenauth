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
module Sthenauth.Providers.OIDC.Public
  ( Public(..)
  , providerId
  , providerName
  , logoUrl
  , providerToPublic
  , publicProviders
  ) where

--------------------------------------------------------------------------------
import Control.Lens.TH (makeLenses)
import Iolaus.Database.Query
import Iolaus.Database.Table (getKey)
import qualified Opaleye as O
import Sthenauth.Core.Error
import Sthenauth.Core.URL
import Sthenauth.Database.Effect
import qualified Sthenauth.Providers.OIDC.Provider as OIDC

--------------------------------------------------------------------------------
-- | Public information about an OIDC provider.
data Public = Public
  { _providerId   :: UUID
  , _providerName :: Text
  , _logoUrl      :: Maybe URL
  }
  deriving stock (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON Public

makeLenses ''Public

--------------------------------------------------------------------------------
-- | Create a public record from an OIDC provider.
providerToPublic :: OIDC.Provider -> Public
providerToPublic p =
  Public
    { _providerId   = getKey (OIDC.providerId p)
    , _providerName = OIDC.providerName p
    , _logoUrl      = OIDC.providerLogoUrl p
    }

--------------------------------------------------------------------------------
-- | Fetch all providers from the database.
publicProviders :: (Has Database sig m, Has Error sig m) => m [Public]
publicProviders =
  providerToPublic <<$>>
    runQuery (select (O.limit 20 OIDC.fromProviders))
