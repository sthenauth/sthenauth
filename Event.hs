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

Records events to an audit log in the database.

-}
module Sthenauth.Core.Event
  ( EventF(..)
  , Event
  , EventId
  , eventId
  , newEvent
  , insertEvent
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Account (AccountId)
import Sthenauth.Core.EventDetail
import Sthenauth.Core.Remote (Remote)

--------------------------------------------------------------------------------
-- | Primary key for the @events@ table.
type EventId = Key UUID EventF

--------------------------------------------------------------------------------
-- | Create an 'EventId'.
eventId :: UUID -> EventId
eventId = Key

--------------------------------------------------------------------------------
-- | Generic details about an event.
data EventF f = Event
  { pk :: Col f "id" EventId SqlUuid ReadOnly
    -- ^ Primary key.

  , actorId :: Col f "actor_id" AccountId SqlUuid Nullable
    -- ^ The account that performed this action.

  , remote :: Col f "remote" Remote SqlJsonb Required
    -- ^ Info about the remote connection that made the request.

  , detail :: Col f "detail" EventDetail SqlJsonb Required
    -- ^ The specific event that fired.

  , createdAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  } deriving Generic

makeTable ''EventF "events"

--------------------------------------------------------------------------------
-- | Monomorphic event.
type Event = EventF ForHask

--------------------------------------------------------------------------------
newEvent :: Maybe AccountId -> Remote -> EventDetail -> EventF SqlWrite
newEvent a r d = Event
  { pk        = Nothing
  , createdAt = Nothing
  , actorId   = O.maybeToNullable (toFields <$> a)
  , remote    = toFields r
  , detail    = toFields d
  }

--------------------------------------------------------------------------------
-- | Try to insert a single event into the database.
insertEvent :: EventF SqlWrite -> Query (Maybe EventId)
insertEvent = insert1 . ins
  where
    ins :: EventF SqlWrite -> Insert [EventId]
    ins e = Insert events [e] (rReturning pk) Nothing
