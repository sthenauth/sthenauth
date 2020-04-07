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
module Sthenauth.Core.Runtime
  ( Runtime(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Control.Monad.Database as DB
import Sthenauth.Core.Config
import Sthenauth.Core.HTTP
import qualified Sthenauth.Core.Crypto as Crypto

--------------------------------------------------------------------------------
-- | Reader environment.
data Runtime = Runtime
  { rtConfig    :: Config
  , rtDb        :: DB.Runtime
  , rtCrypto    :: Crypto.Runtime
  , rtHttp      :: HttpR
  }
