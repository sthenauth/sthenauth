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
module Sthenauth.Core.Error
  ( BaseError(..)
  , AsBaseError(..)
  , UserError(..)
  , AsUserError(..)
  , AsDbError(..)
  , AsCryptoError(..)
  , throwError
  , throwUserError
  , catchError
  , toServerError
  , Error
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Effect.Error (throwError, catchError)
import qualified Control.Effect.Error as Error
import Control.Lens.TH (makeClassyPrisms)
import qualified Data.Aeson as Aeson
import Iolaus.Crypto.Error
import Iolaus.Database.Error
import qualified Iolaus.Validation as Validation
import Servant.Server (ServerError)
import qualified Servant.Server as Servant
import qualified Text.Password.Strength as Zxcvbn

--------------------------------------------------------------------------------
data UserError
  = MustAuthenticateError
  | WeakPasswordError Zxcvbn.Score
  | MustChangePasswordError
  | AuthenticationFailedError (Maybe UUID)
  | UserInputError Text
  | InvalidUsernameOrEmailError
  | AccountAlreadyExistsError
  | OidcProviderAuthenticationFailed
  | ValidationError Validation.Errors
  | NotFoundError
  | PermissionDenied
  deriving (Generic, ToJSON, Show)

makeClassyPrisms ''UserError

--------------------------------------------------------------------------------
-- | Application-level errors.
data BaseError
  = AccountInsertError
  | ApplicationUserError UserError
  | BaseCryptoError CryptoError
  | BaseDatabaseError DbError
  | ConfigLoadError Text
  | MalformedCertError
  | MissingConfigError FilePath
  | MissingDefaultConfigError FilePath FilePath
  | MissingSecretsDir FilePath
  | MissingSiteError
  | RuntimeError Text
  | HttpException SomeException
  | OidcProviderError SomeException
  | OidcProviderInvalidClaimsSet
  | ShellException SomeException
  deriving stock (Generic, Show)
  deriving anyclass Exception

makeClassyPrisms ''BaseError

instance AsDbError BaseError where _DbError = _BaseDatabaseError
instance AsCryptoError BaseError where _CryptoError = _BaseCryptoError
instance AsUserError BaseError where _UserError = _ApplicationUserError

--------------------------------------------------------------------------------
type Error = Error.Error BaseError

--------------------------------------------------------------------------------
throwUserError :: Has Error sig m => UserError -> m a
throwUserError = throwError . ApplicationUserError

--------------------------------------------------------------------------------
toServerError :: BaseError -> ServerError
toServerError = \case
  ApplicationUserError e -> ue e
  _ -> Servant.err500

  where
    mkSE :: (ToJSON a) => a -> ServerError -> ServerError
    mkSE a e = e { Servant.errBody = Aeson.encode a }

    ue :: UserError -> ServerError
    ue e =
      case e of
        MustAuthenticateError            -> mkSE e Servant.err401
        WeakPasswordError _              -> mkSE e Servant.err400
        MustChangePasswordError          -> mkSE e Servant.err400
        AuthenticationFailedError _      -> mkSE e Servant.err401
        UserInputError _                 -> mkSE e Servant.err400
        InvalidUsernameOrEmailError      -> mkSE e Servant.err400
        AccountAlreadyExistsError        -> mkSE e Servant.err400
        OidcProviderAuthenticationFailed -> mkSE e Servant.err401
        ValidationError _                -> mkSE e Servant.err400
        NotFoundError                    -> mkSE e Servant.err404
        PermissionDenied                 -> mkSE e Servant.err403
