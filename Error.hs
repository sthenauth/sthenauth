{-# LANGUAGE TemplateHaskell #-}

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
import Iolaus.Database (AsDBError(_DBError))
import qualified Iolaus.Crypto.Error as Crypto
import qualified Text.Show
import Sthenauth.Types.Error (Error, AsError(..), AsUserError(_UserError))

--------------------------------------------------------------------------------
-- | Errors that can occur when running a 'Command'.
data ShellError
  = MissingConfig FilePath
  | MissingDefaultConfig FilePath FilePath
  | MissingSecretsFile FilePath
  | ShellException SomeException
  | InputError Text
  | SystemError Error

makeClassyPrisms ''ShellError

--------------------------------------------------------------------------------
instance AsError ShellError where
  _Error = _SystemError

instance AsUserError ShellError where
  _UserError = _SystemError . _ApplicationUserError

instance AsDBError ShellError where
  _DBError = _SystemError ._DatabaseError

instance Crypto.AsCryptoError ShellError where
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

    MissingSecretsFile path ->
      mconcat [ "missing encryption keys (secrets) file "
              , "and --init not given, expected to find key at: "
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

    SystemError e ->
      mconcat [ "a system-level error occurred: "
              , show e
              ]
