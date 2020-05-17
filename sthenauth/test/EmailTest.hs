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
--
-- Verify that the email validation package is working correctly.
module EmailTest
  ( test,
  )
where

import Sthenauth.Core.Email
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit

test :: TestTree
test =
  testGroup
    "Email"
    [ testCase "unicode addresses" testUnicodeAddresses
    ]

testUnicodeAddresses :: Assertion
testUnicodeAddresses = do
  shouldPass "senior@example.com" -- ASCII
  shouldPass "señior@example.com" -- Non-ASCII
  where
    shouldPass :: Text -> Assertion
    shouldPass t =
      assertBool
        (toString t <> " should pass")
        (isJust (toEmail t))
