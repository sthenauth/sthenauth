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
  ( Sterr(..)
  , AsSterr(..)
  , UserError(..)
  , AsUserError(..)
  , AsDbError(..)
  , AsCryptoError(..)
  , throwUserError
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeClassyPrisms)
import Data.UUID (UUID)
import Iolaus.Crypto.Error
import Iolaus.Database.Error
import qualified Iolaus.Validation as Validation
import Sthenauth.Core.Encoding
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
  deriving stock (Generic, Show)
  deriving ToJSON via GenericJSON UserError

makeClassyPrisms ''UserError

--------------------------------------------------------------------------------
-- | Library-level errors.
data Sterr
  = AccountInsertError
  | ApplicationUserError UserError
  | BaseCryptoError CryptoError
  | BaseDatabaseError DbError
  | ConfigLoadError Text
  | MalformedCertError
  | MissingConfigError FilePath
  | MissingDefaultConfigError FilePath FilePath
  | MissingSecretsDir FilePath
  | RuntimeError Text
  | HttpException SomeException
  | OidcProviderError SomeException
  | OidcProviderInvalidClaimsSet
  | ShellException SomeException
  deriving stock (Generic, Show)
  deriving anyclass Exception

makeClassyPrisms ''Sterr

instance AsDbError Sterr where _DbError = _BaseDatabaseError
instance AsCryptoError Sterr where _CryptoError = _BaseCryptoError
instance AsUserError Sterr where _UserError = _ApplicationUserError

--------------------------------------------------------------------------------
throwUserError :: Has (Throw Sterr) sig m => UserError -> m a
throwUserError = throwError . ApplicationUserError

--------------------------------------------------------------------------------
-- toServerError :: BaseError -> ServerError
-- toServerError = \case
--   ApplicationUserError e -> ue e
--   _ -> Servant.err500
--
--   where
--     mkSE :: (ToJSON a) => a -> ServerError -> ServerError
--     mkSE a e = e { Servant.errBody = Aeson.encode a }
--
--     ue :: UserError -> ServerError
--     ue e =
--       case e of
--         MustAuthenticateError            -> mkSE e Servant.err401
--         WeakPasswordError _              -> mkSE e Servant.err400
--         MustChangePasswordError          -> mkSE e Servant.err400
--         AuthenticationFailedError _      -> mkSE e Servant.err401
--         UserInputError _                 -> mkSE e Servant.err400
--         InvalidUsernameOrEmailError      -> mkSE e Servant.err400
--         AccountAlreadyExistsError        -> mkSE e Servant.err400
--         OidcProviderAuthenticationFailed -> mkSE e Servant.err401
--         ValidationError _                -> mkSE e Servant.err400
--         NotFoundError                    -> mkSE e Servant.err404
--         PermissionDenied                 -> mkSE e Servant.err403
