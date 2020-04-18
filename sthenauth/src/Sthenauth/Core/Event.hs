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
  , fireEvents
  , newEvent
  , insertEvents
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Time.Clock (UTCTime(..))
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Account (AccountId, accountId)
import Sthenauth.Core.CurrentUser
import Sthenauth.Core.Database
import Sthenauth.Core.Error
import Sthenauth.Core.EventDetail
import Sthenauth.Core.Remote (Remote)
import Sthenauth.Core.Site (SiteId)

--------------------------------------------------------------------------------
-- | Primary key for the @events@ table.
type EventId = Key UUID EventF

--------------------------------------------------------------------------------
-- | Generic details about an event.
data EventF f = Event
  { eventId :: Col f "id" EventId SqlUuid ReadOnly
    -- ^ Primary key.

  , eventSiteId :: Col f "site_id" SiteId SqlUuid ForeignKey
    -- ^ The site this event is for.

  , eventActorId :: Col f "actor_id" AccountId SqlUuid Nullable
    -- ^ The account that performed this action.

  , eventRemote :: Col f "remote" Remote SqlJsonb Required
    -- ^ Info about the remote connection that made the request.

  , eventDetail :: Col f "detail" EventDetail SqlJsonb Required
    -- ^ The specific event that fired.

  , eventCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  } deriving Generic

makeTable ''EventF "events"

--------------------------------------------------------------------------------
-- | Monomorphic event.
type Event = EventF ForHask

--------------------------------------------------------------------------------
-- | Record a series of events.
fireEvents
  :: ( Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => SiteId
  -> CurrentUser
  -> Remote
  -> [EventDetail]
  -> m ()
fireEvents sid user remote details = do
  let es = map (newEvent sid user remote) details
  void (transaction (insertEvents es))

--------------------------------------------------------------------------------
newEvent :: SiteId -> CurrentUser -> Remote -> EventDetail -> EventF SqlWrite
newEvent sid user r d = Event
  { eventId        = Nothing
  , eventCreatedAt = Nothing
  , eventSiteId    = toFields sid
  , eventActorId   = O.maybeToNullable (toFields . accountId <$> toAccount user)
  , eventRemote    = toFields r
  , eventDetail    = toFields d
  }

--------------------------------------------------------------------------------
-- | Try to insert a single event into the database.
insertEvents :: [EventF SqlWrite] -> Query Int64
insertEvents = insert . ins
  where
    ins :: [EventF SqlWrite] -> Insert Int64
    ins es = Insert events es rCount Nothing
