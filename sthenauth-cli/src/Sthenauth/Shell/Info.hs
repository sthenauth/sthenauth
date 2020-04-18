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
module Sthenauth.Shell.Info
  ( main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Aeson.Encode.Pretty (encodePretty)
import Sthenauth.Core.Config

--------------------------------------------------------------------------------
-- | Simple command that dumps the current configuration.
main :: MonadIO m => Config -> m ()
main = liftIO . putLBSLn . encodePretty
