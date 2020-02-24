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
module Sthenauth.Providers.OIDC.Token
  ( BinaryClaimsSet(..)
  , EmailClaim(..)
  , EmailToken
  , tokenSubject
  , toAccessToken

  , SecureEmailToken(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Crypto.JWT (ClaimsSet)
import qualified Data.Aeson as Aeson
import Data.Binary (Binary)
import qualified Data.Binary as Binary
import qualified Web.OIDC.Client as WebOIDC

--------------------------------------------------------------------------------
newtype BinaryClaimsSet = BinaryClaimsSet
  { getClaimsSet :: ClaimsSet }
  deriving (ToJSON, FromJSON) via ClaimsSet

-- So we can encrypt claim sets:
instance Binary BinaryClaimsSet where
  put = Binary.put . Aeson.encode
  get = Aeson.eitherDecode <$> Binary.get >>= either fail pure


--------------------------------------------------------------------------------
data EmailClaim = EmailClaim
  { email         :: Text        -- ^ Email address.
  , emailVerified :: Maybe Bool  -- ^ True if verified.
  }
  deriving stock Generic
  deriving (ToJSON, FromJSON) via GenericJSON EmailClaim

--------------------------------------------------------------------------------
type EmailToken = WebOIDC.Tokens EmailClaim

--------------------------------------------------------------------------------
tokenSubject :: EmailToken -> Text
tokenSubject = WebOIDC.sub . WebOIDC.idToken

--------------------------------------------------------------------------------
toAccessToken :: EmailToken -> Text
toAccessToken = WebOIDC.accessToken

--------------------------------------------------------------------------------
data SecureEmailToken = SecureEmailToken
  { secureAccessToken      :: Secret Text
  , secureRefreshToken     :: Maybe (Secret Text)
  , secureIdentityToken    :: Secret BinaryClaimsSet
  , tokenAccessType        :: Text
  , accessTokenExpiresAt   :: UTCTime
  , identityTokenExpiresAt :: UTCTime
  }
