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
module Sthenauth.Core.EventDetail
  ( EventDetail(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Iolaus.Database.JSON (liftJSON)
import Sthenauth.Core.PostLogin
import Sthenauth.Providers.Local.Login

--------------------------------------------------------------------------------
-- | Specific information about an event.
data EventDetail
  = EventAccountCreated -- ^ A new account was created.
    { newAccountId :: UUID
      -- ^ The ID of the new account.
    }

  | EventFailedLogin -- ^ Someone failed to login.
    { attemptedLogin :: SafeLogin
      -- ^ The username (or email address) given for the login.

    , attemptedAccountId :: Maybe UUID
      -- ^ The account that was being logged into.
    }

  | EventSuccessfulLogin -- ^ Successfully logged in.
    { postLoginDetails :: PostLogin
      -- ^ Where the user went after logging in.
    }

  | EventLogout -- ^ A session was deleted.
    { loggedOutOfAccountId :: UUID
    }

  | EventAdminGranted -- ^ An account was granted admin access.
    { grantedAdminAccountId :: UUID
    }

  | EventAdminRevoked -- ^ Admin access was revoked.
    { revokedAdminAccountId :: UUID
    }

  deriving stock (Generic)
  deriving (FromJSON, ToJSON) via GenericJSON EventDetail

liftJSON ''EventDetail
