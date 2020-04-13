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
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Crypto.JWT (ClaimsSet)
import Data.Aeson as Aeson
import Data.Binary (Binary)
import qualified Data.Binary as Binary

--------------------------------------------------------------------------------
newtype BinaryClaimsSet = BinaryClaimsSet
  { getClaimsSet :: ClaimsSet }
  deriving (ToJSON, FromJSON) via ClaimsSet

-- So we can encrypt claim sets:
instance Binary BinaryClaimsSet where
  put = Binary.put . Aeson.encode
  get = Aeson.eitherDecode <$> Binary.get >>= either fail pure
