-- |
--
-- Copyright:
-- This file is part of the package sthenauth. It is subject to the
-- license terms in the LICENSE file found in the top-level directory
-- of this distribution and at:
--
-- git://code.devalot.com/sthenauth.git
--
-- No part of this package, including this file, may be copied,
-- modified, propagated, or distributed except according to the terms
-- contained in the LICENSE file.
--
-- License: Apache-2.0
module Main
  ( main,
  )
where

import qualified EmailTest
import Test.Tasty

-- | Main.
main :: IO ()
main =
  defaultMain $
    testGroup
      "Sthenauth"
      [ EmailTest.test
      ]
