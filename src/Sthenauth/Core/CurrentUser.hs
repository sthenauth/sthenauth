{-# LANGUAGE Arrows #-}

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
module Sthenauth.Core.CurrentUser
  ( CurrentUser
  , HasCurrentUser(..)
  , notLoggedIn
  , currentUserFromHeaders
  , currentUserFromSessionKey
  , currentUserFromSession
  , sessionKeyFromHeaders
  , sessionFromCurrentUser
  , recordUserActivity
  , toAccount
  , isAdmin
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Control.Lens (Lens')
import Data.List (lookup)
import Data.Time.Clock (UTCTime(..))
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Network.HTTP.Types.Header as HTTP
import qualified Opaleye as O
import Sthenauth.Core.Account
import Sthenauth.Core.Admin
import Sthenauth.Core.Crypto
import Sthenauth.Core.Database
import Sthenauth.Core.Error
import Sthenauth.Core.Remote
import Sthenauth.Core.Session
import Sthenauth.Core.Site
import Web.Cookie

--------------------------------------------------------------------------------
-- | Identify the current user.
data CurrentUser
  = LoggedInAccount Session Account
    -- ^ A normal user is currently logged in.

  | LoggedInAdmin Session Account UTCTime
    -- ^ The logged in user is also an admin.

  | NotLoggedIn
    -- ^ No user is logged in.

--------------------------------------------------------------------------------
-- | For types that can produce a current user.
class HasCurrentUser t where
  currentUser :: Lens' t CurrentUser

--------------------------------------------------------------------------------
-- | Initial state for a current user.
notLoggedIn :: CurrentUser
notLoggedIn = NotLoggedIn

--------------------------------------------------------------------------------
-- | Create a current user by parsing a cookie.
currentUserFromHeaders
  :: ( Has Database      sig m
     , Has Crypto        sig m
     , Has (Throw Sterr) sig m
     )
  => Site
  -> RequestTime
  -> HTTP.RequestHeaders
  -> m CurrentUser
currentUserFromHeaders site rtime hs =
  case sessionKeyFromHeaders hs of
    Nothing  -> return NotLoggedIn
    Just sid -> currentUserFromSessionKey site rtime sid

--------------------------------------------------------------------------------
-- | Create a 'CurrentUser' from the given 'SessionId'.
currentUserFromSessionKey
  :: ( Has Database      sig m
     , Has Crypto        sig m
     , Has (Throw Sterr) sig m
     )
  => Site
  -> RequestTime
  -> ClearSessionKey
  -> m CurrentUser
currentUserFromSessionKey site rtime clear = do
    key <- toSessionKey clear
    user <- runQuery (select1 $ query key) >>= \case
      Nothing -> return NotLoggedIn
      Just (s, a, t) -> pure (unsafeMkCU s a t)
    user <$ recordUserActivity site rtime user
  where
    query
      :: SessionKey
      -> Select (SessionF SqlRead, AccountF SqlRead, AdminF ForceNullable)
    query key = proc () -> do
      (t1, t2) <- findSessionAccount key -< ()
      O.restrict -< accountSiteId t2 O..== O.toFields (siteId site)
      t3 <- accountsAdminJoin -< t2
      returnA -< (t1, t2, t3)

--------------------------------------------------------------------------------
-- | Create a 'CurrentUser' from the given 'Account' and 'Session'.
currentUserFromSession
  :: forall sig m.
     ( Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => Site
  -> RequestTime
  -> Account
  -> Session
  -> m CurrentUser
currentUserFromSession site rtime account session =
  if accountId account == sessionAccountId session &&
     accountSiteId account == siteId site
    then do user <- go
            user <$ recordUserActivity site rtime user
    else return NotLoggedIn

  where
    go :: m CurrentUser
    go = runQuery (select1 query) >>= \case
      Nothing -> return NotLoggedIn
      Just t  -> return (unsafeMkCU session account t)

    query :: O.Select (AdminF ForceNullable)
    query = proc () -> do
      t1 <- fromAccounts -< ()
      t2 <- fromSessions -< ()

      O.restrict -<
        accountId t1 O..== O.toFields (accountId account) O..&&
        sessionAccountId t2 O..== accountId t1 O..&&
        sessionId t2 O..== O.toFields (sessionId session)

      t3 <- accountsAdminJoin -< t1
      returnA -< t3

--------------------------------------------------------------------------------
-- | Internal function to make 'CurrentUser' construction uniform.
unsafeMkCU :: Session -> Account -> AdminF ForceOptional -> CurrentUser
unsafeMkCU session account admin =
  case adminCreatedAt admin of
    Nothing -> LoggedInAccount session account
    Just t  -> LoggedInAdmin   session account t

--------------------------------------------------------------------------------
-- | Extract a session ID from cookie headers.
sessionKeyFromHeaders :: HTTP.RequestHeaders -> Maybe ClearSessionKey
sessionKeyFromHeaders hs = do
  cookies <- parseCookies <$> lookup "Cookie" hs
  sid <- lookup "ss" cookies -- FIXME: don't hardcode ss
  return (ClearSessionKey $ decodeUtf8 sid)

--------------------------------------------------------------------------------
-- | Extract the session from the current user.
sessionFromCurrentUser :: CurrentUser -> Maybe Session
sessionFromCurrentUser = \case
  LoggedInAccount s _   -> Just s
  LoggedInAdmin   s _ _ -> Just s
  NotLoggedIn           -> Nothing

--------------------------------------------------------------------------------
-- | Update the sessions table to reflect that the given user is still active.
recordUserActivity
  :: forall sig m.
     ( Has Database      sig m
     , Has (Throw Sterr) sig m
     )
  => Site
  -> RequestTime
  -> CurrentUser
  -> m ()
recordUserActivity site rtime = \case
    NotLoggedIn         -> pass
    LoggedInAccount s _ -> go s
    LoggedInAdmin s _ _ -> go s
  where
    go :: Session -> m ()
    go = void
       . runQuery
       . update
       . recordSessionActivity (sitePolicy site) rtime
       . sessionId

--------------------------------------------------------------------------------
-- | Extract the account from the current user.
toAccount :: CurrentUser -> Maybe Account
toAccount (LoggedInAccount _ a) = Just a
toAccount (LoggedInAdmin _ a _) = Just a
toAccount NotLoggedIn           = Nothing

--------------------------------------------------------------------------------
-- | Is the current user a system-wide administrator?
isAdmin :: CurrentUser -> Bool
isAdmin LoggedInAdmin{}   = True
isAdmin LoggedInAccount{} = False
isAdmin NotLoggedIn       = False
