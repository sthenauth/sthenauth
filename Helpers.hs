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
-- Library Imports:
import Data.Time.Clock (getCurrentTime)
import Iolaus.Crypto.Password as Crypto
import System.Console.Byline as Byline

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Core.AuthN (asStrongPassword)
import Sthenauth.Shell.Byline
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Run a byline action with a text conversion function.
askWith
  :: forall m a .
     ( MonadByline m
     )
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
  :: forall m e a .
     ( MonadByline m
     , MonadError e m
     , AsSystemError e
     )
  => Maybe Text
  -> Byline IO Text
  -> (Text -> m (Either Text a))
  -> m a
checkOrAsk mt action check =
  case mt of
    Nothing -> askWith action check
    Just t  -> check t >>= \case
      Left e  -> throwing _RuntimeError e
      Right x -> return x

--------------------------------------------------------------------------------
-- | Repeatedly prompt for an email address.
askEmail
  :: ( MonadIO m
     , MonadByline m
     )
  => m Email
askEmail = askWith emailAction checkEmail

--------------------------------------------------------------------------------
-- | Use the given address if present, otherwise prompt for one.
maybeAskEmail
  :: ( MonadIO m
     , MonadByline m
     , MonadError e m
     , AsSystemError e
     )
  => Maybe Text
  -> m Email
maybeAskEmail mt = checkOrAsk mt emailAction checkEmail

--------------------------------------------------------------------------------
-- | Validate an email address.
checkEmail :: (Monad m) => Text -> m (Either Text Email)
checkEmail t = return $
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
  :: ( MonadByline m
     , MonadError e m
     , AsSystemError e
     )
  => Maybe Text
  -> m Text
maybeAskPassword mt =
  checkOrAsk mt (askPassword "Password: " Nothing) (return . Right)

--------------------------------------------------------------------------------
-- | Byline action to prompt and confirm a new password.
askNewPassword
  :: ( MonadIO m
     , MonadByline m
     , MonadCrypto k m
     , MonadError e m
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     )
  => m (Text, Password Strong)
askNewPassword = go
  where
    go = do
      (p, s) <- new
      p' <- liftByline $ askPassword "Confirm Password: " Nothing
      if p == p'
        then return (p, s)
        else liftByline (sayLn (fg red <> "passwords don't match")) >> go

    new = do
      p <- liftByline $ askPassword "New Password: " Nothing
      checkPasswordStrength (Crypto.toPassword p) >>= \case
        Left _  -> liftByline (sayLn ("Weak password!" <> fg red)) >> new
        Right s -> return (p, s)

--------------------------------------------------------------------------------
-- | If @Just@ use the given password, otherwise use byline to prompt
-- for it.
maybeAskNewPassword
  :: ( MonadIO m
     , MonadByline m
     , MonadCrypto k m
     , MonadError e m
     , AsSystemError e
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     )
  => Maybe Text
  -> m (Text, Password Strong)
maybeAskNewPassword = \case
  Nothing -> askNewPassword
  Just t  ->
    checkPasswordStrength (Crypto.toPassword t) >>= \case
      Left e  -> throwing _RuntimeError e
      Right s -> return (t, s)

--------------------------------------------------------------------------------
-- | Verify the strength of a password.
checkPasswordStrength
  :: ( MonadIO m
     , MonadCrypto k m
     , MonadError e m
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     )
  => Password Clear
  -> m (Either Text (Password Strong))
checkPasswordStrength p = do
  time <- liftIO getCurrentTime
  catching _WeakPasswordError (Right <$> asStrongPassword time p) handleError

  where
    handleError = return . Left . show
