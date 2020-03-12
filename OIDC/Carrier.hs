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
module Sthenauth.Providers.OIDC.Carrier
  ( OidcC
  , runOidc
  ) where

--------------------------------------------------------------------------------
import Control.Carrier.Reader
import Network.HTTP.Client (Manager)

--------------------------------------------------------------------------------
newtype OidcC m a = OidcC
  { runOidcC :: ReaderC Manager m a }
  deriving newtype (Functor, Applicative, Monad, MonadIO)



--------------------------------------------------------------------------------
runOidc :: Manager -> OidcC m a -> m a
runOidc mgr = runReader mgr . runOidcC
