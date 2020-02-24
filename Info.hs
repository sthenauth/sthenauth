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
-- Library Imports:
import Data.Aeson.Encode.Pretty (encodePretty)
import qualified Data.ByteString.Lazy as LByteString

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command
import Sthenauth.Shell.Options (Options)

--------------------------------------------------------------------------------
-- | Simple command that dumps the current configuration.
main :: Options a -> Command ()
main _ = do
  cfg <- currentConfig
  liftIO $ LByteString.putStr (encodePretty cfg)
