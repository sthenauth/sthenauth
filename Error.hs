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
module Sthenauth.Shell.Error
  ( ShellError(..)
  , AsShellError(..)
  ) where


--------------------------------------------------------------------------------
-- Library Imports:
import Control.Exception (SomeException)
import Control.Lens.TH (makeClassyPrisms)
import Iolaus.Crypto.Error
import Iolaus.Database.Error
import Sthenauth.Types.Error
import qualified Text.Show

--------------------------------------------------------------------------------
-- | Errors that can occur when running a 'Command'.
data ShellError
  = MissingConfig FilePath
  | MissingDefaultConfig FilePath FilePath
  | MissingSecretsDir FilePath
  | ShellException SomeException
  | InputError Text
  | SError SystemError

makeClassyPrisms ''ShellError

--------------------------------------------------------------------------------
instance AsSystemError ShellError where
  _SystemError = _SError

instance AsUserError ShellError where
  _UserError = _SystemError . _ApplicationUserError

instance AsDbError ShellError where
  _DbError = _SystemError ._SystemDatabaseError

instance AsCryptoError ShellError where
  _CryptoError = _SystemError . _CryptoError

--------------------------------------------------------------------------------
instance Show ShellError where
  show = \case
    MissingConfig path ->
      mconcat [ "missing configuration and --init not given, "
              , "expected to find config file at: "
              , path
              ]

    MissingDefaultConfig src dest ->
      mconcat [ "missing default configuration: "
              , "expected to find default config at: "
              , dest
              , " in order to produce path: "
              , src
              ]

    MissingSecretsDir path ->
      mconcat [ "missing encryption keys (secrets) dir "
              , "and --init not given, expected to find keys in: "
              , path
              ]

    ShellException e ->
      mconcat [ "a error occurred while performing an I/O operation: "
              , show e
              ]

    InputError t ->
      mconcat [ "unable to continue due to invalid input: "
              , toString t
              ]

    SError e ->
      mconcat [ "a system-level error occurred: "
              , show e
              ]
