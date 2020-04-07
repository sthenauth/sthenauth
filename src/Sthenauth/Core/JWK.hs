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
module Sthenauth.Core.JWK
  ( JWK
  , JOSE.JWKSet
  , getJWK
  , KeyUse(..)
  , SqlKeyUse
  , newJWK
  ) where

--------------------------------------------------------------------------------
import Crypto.Hash (Digest, SHA256)
import qualified Crypto.JOSE as JOSE
import qualified Crypto.JOSE.JWA.JWE.Alg as JOSE
import qualified Data.Aeson as Aeson
import Data.Binary (Binary)
import qualified Data.Binary as Binary
import Data.Profunctor (dimap)
import Data.Profunctor.Product.Default (Default(..))
import qualified Data.Text as Text
import Opaleye.SqlTypes

import Opaleye
  ( Constant(..)
  , QueryRunnerColumnDefault(..)
  , Column
  , fieldQueryRunnerColumn
  , unsafeCast
  )

import Database.PostgreSQL.Simple.FromField
  ( FromField(..)
  , ResultError(..)
  , returnError
  )

--------------------------------------------------------------------------------
-- | JSON Web Key.
newtype JWK = JWK { getJWK :: JOSE.JWK }

-- So we can encrypt JWKs:
instance Binary JWK where
  put = Binary.put . Aeson.encode . getJWK
  get = Aeson.eitherDecode <$> Binary.get >>= either fail (pure . JWK)

--------------------------------------------------------------------------------
-- | What a key can be used for.
data KeyUse = Sig | Enc
  deriving (Generic, Show, Eq, ToJSON, FromJSON)

--------------------------------------------------------------------------------
-- | For table definitions:
data SqlKeyUse

--------------------------------------------------------------------------------
-- | Convert a 'KeyUse' to 'Text'.
fromKeyUse :: KeyUse -> Text
fromKeyUse = Text.toLower . show

--------------------------------------------------------------------------------
-- | Convert a 'Text' to a 'KeyUse'.
toKeyUse :: (MonadPlus m) => Text -> m KeyUse
toKeyUse "sig" = pure Sig
toKeyUse "enc" = pure Enc
toKeyUse _     = mzero

--------------------------------------------------------------------------------
-- | Set the "use" field of a JWK.
setKeyUse :: KeyUse -> JOSE.JWK -> JOSE.JWK
setKeyUse u = JOSE.jwkUse ?~
  case u of
    Sig -> JOSE.Sig
    Enc -> JOSE.Enc

--------------------------------------------------------------------------------
setKeyAlg :: KeyUse -> JOSE.JWK -> JOSE.JWK
setKeyAlg u = JOSE.jwkAlg ?~
  case u of
    Sig -> JOSE.JWSAlg JOSE.RS256
    Enc -> JOSE.JWEAlg JOSE.A256KW

--------------------------------------------------------------------------------
instance FromField KeyUse where
  fromField f mdata =
    case mdata of
      Just bs -> toKeyUse (decodeUtf8 bs)
      Nothing -> returnError ConversionFailed f "Unexpected empty value"

instance QueryRunnerColumnDefault SqlKeyUse KeyUse where
  queryRunnerColumnDefault = fieldQueryRunnerColumn

instance Default Constant KeyUse (Column SqlKeyUse) where
  def = dimap fromKeyUse (unsafeCast "key_use_t") def_
    where def_ :: Constant Text (Column SqlText)
          def_ = def

--------------------------------------------------------------------------------
-- | Generate a new JWK.
newJWK :: MonadRandom m => KeyUse -> m (JWK, Text)
newJWK keyuse = do
  jwk <- JOSE.genJWK (JOSE.RSAGenParam (4096 `div` 8))

  let h = jwk ^. JOSE.thumbprint :: Digest SHA256
      kid = h ^. (re (JOSE.base64url . JOSE.digest) . utf8)

      final = jwk &
                JOSE.jwkKid ?~ kid &
                setKeyUse keyuse &
                setKeyAlg keyuse

  pure (JWK final, kid)
