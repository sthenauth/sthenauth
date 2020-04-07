{-# LANGUAGE Arrows #-}

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
module Sthenauth.Core.Client
  ( Client
  , ClientF(..)
  , ClientId
  , newClient
  , authenticateClient
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import qualified Iolaus.Crypto.Password as Crypto
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Error
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect

--------------------------------------------------------------------------------
-- | Client IDs.
type ClientId = Key UUID ClientF

--------------------------------------------------------------------------------
-- | Self-assigned client name.
type ClientName = Text

--------------------------------------------------------------------------------
-- | Clients.
data ClientF f = Client
  { clientId :: Col f "id" ClientId SqlUuid ReadOnly
    -- ^ Primary key.

  , clientEnabled :: Col f "enabled" Bool SqlBool ReadOnly
    -- ^ Is this client allowed to use the API?

  , clientName :: Col f "client_name" ClientName SqlText Required
    -- ^ The name the client identified itself as.

  , clientToken :: Col f "token" (Password Hashed) SqlJsonb Required
    -- ^ The hashed password that the client needs to use.

  , clientCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  , clientUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was last updated.
  }

makeTable ''ClientF "clients"

--------------------------------------------------------------------------------
-- | Monomorphic type alias.
type Client = ClientF ForHask

--------------------------------------------------------------------------------
-- |  Create a new client that is ready to insert into the database.
--
-- The insert record is returned along with a clear-text password that
-- should be issued to the client for future session.
newClient
  :: Has Crypto sig m
  => ClientName
  -> m (Text, Insert Int64)
newClient name = do
    (clear, hashed) <- generatePassword

    pure . (clear,) . toInsert $
      Client
        { clientId        = Nothing
        , clientEnabled   = Nothing
        , clientName      = toFields name
        , clientToken     = toFields hashed
        , clientCreatedAt = Nothing
        , clientUpdatedAt = Nothing
        }

  where
    toInsert :: ClientF SqlWrite -> Insert Int64
    toInsert c = Insert clients [c] rCount Nothing

--------------------------------------------------------------------------------
-- | Fetch and authenticate a client.
authenticateClient
  :: forall sig m.
     ( Has Database sig m
     , Has Crypto   sig m
     , Has Error    sig m
     )
  => UUID
  -> Text
  -> m (Maybe Client)
authenticateClient uuid clear =
  runQuery (select1 $ clientById uuid) >>= \case
    Nothing -> pure Nothing
    Just c  -> verify c
  where
    verify :: Client -> m (Maybe Client)
    verify client =
      verifyPassword (Crypto.toPassword clear) (clientToken client) >>= \case
        PasswordMismatch ->
          pure Nothing
        PasswordsMatch ->
          pure (Just client)
        PasswordNeedsUpgrade ->
          pure (Just client) -- FIXME: upgrade the password.

--------------------------------------------------------------------------------
-- | Select from the clients table.
fromClients :: Select (ClientF SqlRead)
fromClients = proc () -> do
  t <- selectTable clients -< ()
  O.restrict -< clientEnabled t
  returnA -< t

--------------------------------------------------------------------------------
-- | Query to find a client using its ID.
clientById :: UUID -> Select (ClientF SqlRead)
clientById uuid = proc () -> do
  t <- fromClients -< ()
  O.restrict -< (clientId t .== toFields uuid)
  returnA -< t
