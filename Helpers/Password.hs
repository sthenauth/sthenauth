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
module Sthenauth.Shell.Helpers.Password
  ( askNewPassword
  , maybeAskNewPassword
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Data.Time.Clock (getCurrentTime)
import Iolaus.Crypto as Crypto
import System.Console.Byline

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Core.AuthN (asStrongPassword)
import Sthenauth.Shell.Error
import Sthenauth.Types

--------------------------------------------------------------------------------
-- | Byline action to prompt and confirm a new password.
newPasswordAction
  :: ( MonadIO m
     , MonadCrypto m
     , MonadError e m
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     )
  => Byline m (Password Strong)
newPasswordAction = go
  where
    go = do
      p <- askPassword "New Password: " Nothing
      s <- lift (checkPasswordStrength . Crypto.password $ p) >>= \case
        Left e -> say (fg red <> text e) >> go
        Right x -> return x
      p' <- askPassword "Confirm Password: " Nothing
      if p == p'
        then return s
        else say (fg red <> "passwords don't match") >> go

--------------------------------------------------------------------------------
-- | Ask and verify a password or throw an error.
askNewPassword
  :: ( MonadIO m
     , MonadMask m
     , MonadCrypto m
     , MonadError e m
     , AsShellError e
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     )
  => m (Password Strong)
askNewPassword =
  runByline newPasswordAction >>= \case
    Just x -> return x
    Nothing -> throwing _InputError "expected new password"

--------------------------------------------------------------------------------
-- | If @Just@ use the given password, otherwise use byline to prompt
-- for it.
maybeAskNewPassword
  :: ( MonadIO m
     , MonadMask m
     , MonadCrypto m
     , MonadError e m
     , AsShellError e
     , AsUserError e
     , MonadReader r m
     , HasConfig r
     )
  => Maybe Text
  -> m (Password Strong)
maybeAskNewPassword = \case
  Nothing -> askNewPassword
  Just t -> checkPasswordStrength (Crypto.password t) >>= \case
    Left e -> throwing _InputError e
    Right p -> return p

--------------------------------------------------------------------------------
-- | Verify the strength of a password.
checkPasswordStrength
  :: ( MonadIO m
     , MonadCrypto m
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
