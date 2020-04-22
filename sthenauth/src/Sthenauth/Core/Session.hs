{-# LANGUAGE Arrows #-}

-- |
--
-- Copyright:
--   This file is part of the package sthenauth. It is subject to the
--   license terms in the LICENSE file found in the top-level directory
--   of this distribution and at:
--
--     git://code.devalot.com/sthenauth.git
--
--   No part of this package, including this file, may be copied,
--   modified, propagated, or distributed except according to the terms
--   contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.Core.Session
  ( SessionF (..),
    Session,
    fromSessions,
    SessionId,
    resetSessionCookie,
    makeSessionCookie,
    SessionKey,
    ClearSessionKey (..),
    toSessionKey,
    newSessionKey,
    recordSessionActivity,
    issueSession,
    newSession,
    insertSession,
    deleteSession,
    findSessionQuery,
    findSessionAccount,
    encodeSessionId,
    decodeSessionId,
    deleteExpiredSessions,
  )
where

import Control.Arrow (returnA)
import Control.Lens ((^.))
import Data.Aeson (FromJSON (..), ToJSON (..))
import qualified Data.Binary as Binary
import Data.ByteArray.Encoding (Base (..), convertFromBase, convertToBase)
import qualified Data.ByteString.Lazy as LByteString
import Data.Time.Calendar (Day (..))
import Data.Time.Clock (UTCTime (..))
import Iolaus.Crypto.Salt
import Iolaus.Database.Extra
import Iolaus.Database.JSON (liftJSON)
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Relude.Extra.Tuple (traverseToSnd)
import Sthenauth.Core.Account
import Sthenauth.Core.Crypto
import Sthenauth.Core.Database
import Sthenauth.Core.Error
import Sthenauth.Core.Policy
import Sthenauth.Core.Remote
import Sthenauth.Core.Site (Site, SiteF (..), SiteId)
import Web.Cookie

-- | Wrapper around signed JSON web tokens.
newtype JWT = JWT {getJWT :: Text}

instance ToJSON JWT where
  toJSON = toJSON . getJWT

instance FromJSON JWT where
  parseJSON = fmap JWT . parseJSON

liftJSON ''JWT

-- | The primary key for the @sessions@ table.
type SessionId = Key UUID SessionF

-- | Hashed key used to identify a session.  Only the account owner
-- should have the plain text version of this key.
type SessionKey = SaltedHash Text

-- | An unprotected session key.
newtype ClearSessionKey = ClearSessionKey Text

-- | The sessions table in the database.
data SessionF f = Session
  { -- | Primary key.
    sessionId :: Col f "id" SessionId SqlUuid ReadOnly,
    -- | Hashed key for looking up a session.
    sessionKey :: Col f "session_key" SessionKey SqlBytea Required,
    -- | The site this session is for.
    sessionSiteId :: Col f "site_id" SiteId SqlUuid ForeignKey,
    -- | The account this email address is for (foreign key).
    sessionAccountId :: Col f "account_id" AccountId SqlUuid ForeignKey,
    -- | Info about the remote connection that requested the session.
    sessionRemote :: Col f "remote" Remote SqlJsonb Required,
    -- | The time this session will expire and no longer be valid.
    sessionExpiresAt :: Col f "expires_at" UTCTime SqlTimestamptz Required,
    -- | The time this session will be marked inactive and no longer valid.
    sessionInactiveAt :: Col f "inactive_at" UTCTime SqlTimestamptz Required,
    -- | The time this record was created.
    sessionCreatedAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly,
    -- | The time this record was last updated.
    sessionUpdatedAt :: Col f "updated_at" UTCTime SqlTimestamptz ReadOnly
  }
  deriving (Generic)

makeTable ''SessionF "sessions"

-- | Monomorphic session.
type Session = SessionF ForHask

-- | Generate a cookie for clearing the session.
resetSessionCookie :: Text -> SetCookie
resetSessionCookie name =
  defaultSetCookie
    { setCookieName = encodeUtf8 name,
      setCookieValue = "",
      setCookiePath = Just "/",
      setCookieExpires = Just (UTCTime (ModifiedJulianDay 0) 0),
      setCookieHttpOnly = True,
      setCookieSecure = True
    }

-- | Create a new session cookie.
makeSessionCookie :: Text -> ClearSessionKey -> Session -> SetCookie
makeSessionCookie name (ClearSessionKey key) Session {sessionExpiresAt} =
  (resetSessionCookie name)
    { setCookieValue = encodeUtf8 key,
      setCookieExpires = Just sessionExpiresAt
    }

toSessionKey :: Has Crypto sig m => ClearSessionKey -> m SessionKey
toSessionKey (ClearSessionKey clear) = toSaltedHash clear

newSessionKey :: Has Crypto sig m => m (ClearSessionKey, SessionKey)
newSessionKey = do
  key <- ClearSessionKey . encodeSalt <$> generateSaltSized 32
  traverseToSnd toSessionKey key

newSession ::
  Site ->
  AccountId ->
  Remote ->
  SessionKey ->
  SessionF SqlWrite
newSession site account remote key =
  let policy = sitePolicy site
      rtime = remote ^. requestTime
   in Session
        { sessionId = Nothing,
          sessionCreatedAt = Nothing,
          sessionUpdatedAt = Nothing,
          sessionKey = toFields key,
          sessionExpiresAt = toFields (sessionExpire policy rtime),
          sessionInactiveAt = toFields (sessionInactive policy rtime),
          sessionSiteId = toFields (siteId site),
          sessionAccountId = toFields account,
          sessionRemote = toFields remote
        }

-- Issue a brand new session to the given account.
issueSession ::
  ( Has Database sig m,
    Has Crypto sig m,
    Has (Throw Sterr) sig m
  ) =>
  Site ->
  Remote ->
  Account ->
  m (Session, ClearSessionKey)
issueSession site remote acct = do
  (clear, key) <- newSessionKey
  let policy = sitePolicy site
      sessionW = newSession site (accountId acct) remote key
      query = insertSession (policy ^. maxSessionsPerAccount) sessionW
  transaction query >>= \case
    Nothing -> throwError (RuntimeError "failed to create a session")
    Just session -> return (session, clear)

-- | Try to insert a single session into the database.
--
-- If the account is over their session limit, delete the oldest
-- session before continuing.
--
-- NOTE: Run this inside a transaction.
insertSession ::
  -- | Maximum number of sessions allowed per account.
  Int64 ->
  -- | The new session.
  SessionF SqlWrite ->
  Query (Maybe Session)
insertSession m s = do
  existing <- count forAcct
  when (existing >= m) $
    (listToMaybe <$> select oldest) >>= \case
      Nothing -> pass
      Just (sid, _ :: UTCTime) -> deleteSession sid
  listToMaybe <$> insert ins
  where
    ins :: Insert [Session]
    ins = Insert sessions [s] (rReturning id) Nothing
    forAcct :: O.Select (SessionF SqlRead)
    forAcct = proc () -> do
      t <- O.selectTable sessions -< ()
      O.restrict -< sessionAccountId t .== sessionAccountId s
      returnA -< t
    oldest :: O.Select (O.Column SqlUuid, O.Column SqlTimestamptz)
    oldest = O.orderBy (O.asc snd) $ O.limit 1 $
      proc () -> do
        t <- forAcct -< ()
        returnA -< (sessionId t, sessionCreatedAt t)

-- | Delete the given session.
deleteSession :: SessionId -> Query ()
deleteSession = void . delete . rm . getKey
  where
    rm :: UUID -> Delete Int64
    rm sid = Delete sessions (\t -> sessionId t .== toFields sid) O.rCount

findSessionQuery :: SiteId -> SessionKey -> O.SelectArr (SessionF SqlRead) ()
findSessionQuery sid key = proc t ->
  O.restrict
    -<
      sessionKey t .== toFields key
        .&& sessionSiteId t .== toFields sid

fromSessions :: Select (SessionF SqlRead)
fromSessions = proc () -> do
  t <- selectTable sessions -< ()
  O.restrict
    -<
      sessionExpiresAt t .> transactionTimestamp
        .&& sessionInactiveAt t .> transactionTimestamp
  returnA -< t

findSessionAccount ::
  SiteId ->
  SessionKey ->
  O.Select (SessionF SqlRead, AccountF SqlRead)
findSessionAccount sid key = proc () -> do
  a <- fromAccounts -< ()
  t <- fromSessions -< ()
  findSessionQuery sid key -< t
  O.restrict -< accountId a .== sessionAccountId t
  returnA -< (t, a)

-- | A @DELETE@ statement that will remove expired sessions.
--
-- @since 0.1.0.0
deleteExpiredSessions :: Delete Int64
deleteExpiredSessions =
  Delete
    { dTable = sessions,
      dReturning = rCount,
      dWhere = \t -> sessionExpiresAt t .>= transactionTimestamp
    }

-- | Update the inactive time of a session.
recordSessionActivity ::
  -- | The policy controlling the timeout.
  Policy ->
  -- | The current time.
  UTCTime ->
  -- | The session ID to update.
  SessionId ->
  Update Int64
recordSessionActivity policy now sid =
  let newTime = sessionInactive policy now
   in Update
        { uTable = sessions,
          uUpdateWith = O.updateEasy (\t -> t {sessionInactiveAt = toFields newTime}),
          uWhere = \t -> sessionId t .== toFields sid,
          uReturning = O.rCount
        }

-- | Encode a session ID as text that can be sent over the network.
encodeSessionId :: SessionId -> ByteString
encodeSessionId =
  getKey
    >>> Binary.encode
    >>> toStrict
    >>> convertToBase Base64URLUnpadded

-- Attempt to decode a session ID that was previously encoded with the
-- 'encodeSessionId' function.
decodeSessionId :: ByteString -> Maybe SessionId
decodeSessionId bs = do
  bytes <- rightToMaybe (convertFromBase Base64URLUnpadded bs)
  (bs', _, key) <- rightToMaybe (Binary.decodeOrFail (toLazy bytes))
  if LByteString.null bs'
    then pure (Key key)
    else Nothing
