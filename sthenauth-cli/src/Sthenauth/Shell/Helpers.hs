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
module Sthenauth.Shell.Helpers
  ( askWith
  , checkOrAsk
  , askEmail
  , maybeAskEmail
  , maybeAskPassword
  , askNewPassword
  , maybeAskNewPassword
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Time.Clock (getCurrentTime)
import Iolaus.Crypto.Password as Crypto
import Sthenauth.Core.Crypto
import Sthenauth.Core.Email
import Sthenauth.Core.Error
import Sthenauth.Core.Policy
import Sthenauth.Providers.Local.Password (asStrongPassword)
import Sthenauth.Shell.Byline
import System.Console.Byline as Byline

--------------------------------------------------------------------------------
-- | Run a byline action with a text conversion function.
askWith
  :: forall sig m a. Has LiftByline sig m
  => Byline IO Text
  -> (Text -> m (Either Text a))
  -> m a
askWith action check =
    go
  where
    go :: m a
    go = liftByline action >>= check >>= \case
      Left e  -> liftByline (say (fg red <> text e)) >> go
      Right x -> return x

--------------------------------------------------------------------------------
-- | If given a @Just@, try to parse it.  If given @Nothing@, call 'askWith'.
checkOrAsk
  :: forall sig m a .
     (Has LiftByline sig m, Has (Throw Sterr) sig m)
  => Maybe Text
  -> Byline IO Text
  -> (Text -> m (Either Text a))
  -> m a
checkOrAsk mt action check =
  case mt of
    Nothing -> askWith action check
    Just t  -> check t >>= \case
      Left e  -> throwError (RuntimeError e)
      Right x -> return x

--------------------------------------------------------------------------------
-- | Repeatedly prompt for an email address.
askEmail
  :: Has LiftByline sig m
  => m Email
askEmail = askWith emailAction (pure . checkEmail)

--------------------------------------------------------------------------------
-- | Use the given address if present, otherwise prompt for one.
maybeAskEmail
  :: (Has LiftByline sig m, Has (Throw Sterr) sig m)
  => Maybe Text
  -> m Email
maybeAskEmail mt = checkOrAsk mt emailAction (pure . checkEmail)

--------------------------------------------------------------------------------
-- | Validate an email address.
checkEmail :: Text -> Either Text Email
checkEmail t =
  case toEmail t of
    Nothing -> Left "invalid email address\n"
    Just e  -> Right e

--------------------------------------------------------------------------------
-- | A byline action for reading email addresses.
emailAction :: (MonadIO m) => Byline m Text
emailAction = Byline.ask "Email Address: " Nothing

--------------------------------------------------------------------------------
-- | Ask for a password if the given text is 'Nothing'.
maybeAskPassword
  :: (Has LiftByline sig m, Has (Throw Sterr) sig m)
  => Maybe Text
  -> m Text
maybeAskPassword mt =
  checkOrAsk mt (askPassword "Password: " Nothing) (return . Right)

--------------------------------------------------------------------------------
-- | Byline action to prompt and confirm a new password.
askNewPassword
  :: ( MonadIO m
     , Has LiftByline sig m
     , Has Crypto sig m
     , Has (Error Sterr) sig m
     )
  => Policy
  -> m (Text, Password Strong)
askNewPassword policy = go
  where
    go = do
      (p, s) <- new
      p' <- liftByline $ askPassword "Confirm Password: " Nothing
      if p == p'
        then return (p, s)
        else liftByline (sayLn (fg red <> "passwords don't match")) >> go

    new = do
      p <- liftByline $ askPassword "New Password: " Nothing
      checkPasswordStrength policy (Crypto.toPassword p) >>= \case
        Left _  -> liftByline (sayLn ("Weak password!" <> fg red)) >> new
        Right s -> return (p, s)

--------------------------------------------------------------------------------
-- | If @Just@ use the given password, otherwise use byline to prompt
-- for it.
maybeAskNewPassword
  :: ( MonadIO m
     , Has LiftByline sig m
     , Has Crypto sig m
     , Has (Error Sterr) sig m
     )
  => Policy
  -> Maybe Text
  -> m (Text, Password Strong)
maybeAskNewPassword policy = \case
  Nothing -> askNewPassword policy
  Just t  ->
    checkPasswordStrength policy (Crypto.toPassword t) >>= \case
      Left e  -> throwError (RuntimeError e)
      Right s -> return (t, s)

--------------------------------------------------------------------------------
-- | Verify the strength of a password.
checkPasswordStrength
  :: forall sig m.
     ( MonadIO m
     , Has Crypto sig m
     , Has (Error Sterr) sig m
     )
  => Policy
  -> Password Clear
  -> m (Either Text (Password Strong))
checkPasswordStrength policy p = do
    time <- liftIO getCurrentTime
    catchError (Right <$> asStrongPassword policy time p) handleError
  where
    handleError :: Sterr -> m (Either Text (Password Strong))
    handleError (ApplicationUserError w@(WeakPasswordError _)) = pure (Left (show w))
    handleError e = throwError e
