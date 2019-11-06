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
module Sthenauth.Shell.Helpers.Email
  ( askEmail
  , maybeAskEmail
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import System.Console.Byline as Byline

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Types.Email
import Sthenauth.Shell.Error
import Sthenauth.Shell.Helpers.Byline

--------------------------------------------------------------------------------
-- | Repeatedly prompt for an email address.
askEmail
  :: ( MonadIO m
     , MonadMask m
     , MonadError e m
     , AsShellError e
     )
  => m (Email Address)
askEmail = askWith emailAction checkEmail

--------------------------------------------------------------------------------
-- | Use the given address if present, otherwise prompt for one.
maybeAskEmail
  :: ( MonadIO m
     , MonadMask m
     , MonadError e m
     , AsShellError e
     )
  => Maybe Text
  -> m (Email Address)
maybeAskEmail mt = checkOrAsk mt emailAction checkEmail

--------------------------------------------------------------------------------
-- | Validate an email address.
checkEmail :: (Monad m) => Text -> m (Either Text (Email Address))
checkEmail t = return $
  case email t of
    Nothing -> Left "invalid email address"
    Just e  -> Right e

--------------------------------------------------------------------------------
-- | A byline action for reading email addresses.
emailAction :: (MonadIO m) => Byline m Text
emailAction = Byline.ask "Email Address: " Nothing
