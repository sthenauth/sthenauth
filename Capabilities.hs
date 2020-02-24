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
module Sthenauth.Core.Capabilities
  ( Capabilities(..)
  , toCapabilities
  ) where

--------------------------------------------------------------------------------
import qualified Data.List.NonEmpty as NonEmpty
import Data.Set (Set)
import qualified Data.Set as Set
import Sthenauth.Core.Config
import Sthenauth.Core.Policy
import qualified Sthenauth.Providers.OIDC.Public as OIDC

--------------------------------------------------------------------------------
-- | Similar to a 'Policy', except that the fields in this record are
-- safe to disclose to the public.  Additionally, they are filtered by
-- what is enabled in the configuration.
data Capabilities = Capabilities
  { canCreateLocalAccount :: Bool
    -- ^ Whether or not users can create their own local accounts.

  , localPrimaryAuthenticators :: Set Authenticator
    -- ^ When authenticating for a local account, which authenticators
    -- are allowed.

  , localSecondaryAuthenticators :: Map Authenticator (NonEmpty Authenticator)
    -- ^ When authenticating for a local account, which primary
    -- authenticators require a secondary authentication method?

  , oidcProviders :: [OIDC.Public]
    -- ^ List of OIDC providers.
  }
  deriving (Generic, Show)
  deriving (ToJSON) via GenericJSON Capabilities

--------------------------------------------------------------------------------
-- | Generate a 'Capabilities' record.
toCapabilities :: Config -> Policy -> [OIDC.Public] -> Capabilities
toCapabilities config policy oidc =
  Capabilities
    { canCreateLocalAccount =
        openLocalAccountCreation policy

    , localPrimaryAuthenticators =
        let x = toS $ policy ^. (assuranceLevel.primaryAuthenticators)
            y = toS $ enabledAuthenticators config
        in x `Set.intersection` y

    , localSecondaryAuthenticators =
        policy ^. (assuranceLevel.secondaryAuthenticators)

    , oidcProviders = oidc
    }

  where
    toS :: (Ord a) => NonEmpty a -> Set a
    toS = Set.fromList . NonEmpty.toList
