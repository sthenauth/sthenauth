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
module Sthenauth.Effect.Runtime
  ( Runtime(..)
  , Environment(..)
  , TState(..)
  , config
  , crypto
  , currentTime
  , database
  , env
  , httpr
  , site
  , remote
  , tstate
  , user
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens (Lens', makeLenses)
import qualified Control.Monad.Database as DB
import Data.Time.Clock (UTCTime)
import Sthenauth.Core.Config
import qualified Sthenauth.Core.Crypto as Crypto
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.HTTP
import Sthenauth.Core.Remote
import Sthenauth.Core.Site (Site)

--------------------------------------------------------------------------------
-- | Reader environment shared by all threads.
data Environment = Environment
  { _database :: DB.Runtime
  , _crypto   :: Crypto.Runtime
  , _httpr    :: HttpR
  , _config   :: Config
  }

makeLenses ''Environment

--------------------------------------------------------------------------------
-- | Thread state.
data TState = TState
  { _user     :: IORef CurrentUser
  , _remote   :: Remote
  , _site     :: Site
  }

makeLenses ''TState

--------------------------------------------------------------------------------
data Runtime = Runtime
  { _env    :: Environment
  , _tstate :: TState
  }

makeLenses ''Runtime

--------------------------------------------------------------------------------
currentTime :: Lens' Runtime UTCTime
currentTime = tstate . remote . requestTime
