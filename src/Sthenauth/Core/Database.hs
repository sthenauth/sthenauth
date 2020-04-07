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
module Sthenauth.Core.Database
  ( runQuery
  , runQuery_
  , transaction
  , transaction_
  , module Control.Effect.Database
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Effect.Database hiding (runQuery, transaction)
import Iolaus.Database.Query
import Sthenauth.Core.Error

--------------------------------------------------------------------------------
-- | Run a query and capture errors into a 'BaseDatabaseError'.
runQuery :: (Has Database sig m, Has (Throw Sterr) sig m) => Query a -> m a
runQuery = runQueryEither >=> either (throwError . BaseDatabaseError) pure

--------------------------------------------------------------------------------
-- | Like 'runQuery' but ignores the result.
runQuery_ :: (Has Database sig m, Has (Throw Sterr) sig m) => Query a -> m ()
runQuery_ = void . runQuery

--------------------------------------------------------------------------------
-- | Run a transaction and capture errors into a 'BaseDatabaseError'.
transaction :: (Has Database sig m, Has (Throw Sterr) sig m) => Query a -> m a
transaction = transactionEither >=> either (throwError . BaseDatabaseError) pure

--------------------------------------------------------------------------------
-- | Like 'transaction' but ignores the result.
transaction_ :: (Has Database sig m, Has (Throw Sterr) sig m) => Query a -> m ()
transaction_ = void . transaction
