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
module Sthenauth.Shell.Helpers.Byline
  ( askWith
  , checkOrAsk
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import System.Console.Byline

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Error

--------------------------------------------------------------------------------
-- | Run a byline action with a text conversion function.
askWith
  :: forall m e a .
     ( MonadIO m
     , MonadMask m
     , MonadError e m
     , AsShellError e
     )
  => Byline m Text
  -> (Text -> m (Either Text a))
  -> m a
askWith action check =
  runByline go >>= \case
    Nothing -> throwing _InputError "unexpected termination"
    Just x  -> return x

  where
    go :: Byline m a
    go = action >>= lift . check >>= \case
      Left e  -> say (fg red <> text e) >> go
      Right x -> return x

--------------------------------------------------------------------------------
-- | If given a @Just@, try to parse it.  If given @Nothing@, call 'askWith'.
checkOrAsk
  :: forall m e a .
     ( MonadIO m
     , MonadMask m
     , MonadError e m
     , AsShellError e
     )
  => Maybe Text
  -> Byline m Text
  -> (Text -> m (Either Text a))
  -> m a
checkOrAsk mt action check =
  case mt of
    Nothing -> askWith action check
    Just t  -> check t >>= \case
      Left e  -> throwing _InputError e
      Right x -> return x
