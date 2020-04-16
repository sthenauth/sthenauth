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
module Sthenauth.API.Monad
  ( Action
  , runRequest
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Carrier.Error.Either (ErrorC)
import Control.Carrier.Lift (LiftC)
import Control.Lens ((^.), _2)
import qualified Control.Monad.Except as CME
import Data.Aeson (ToJSON)
import qualified Data.Aeson as Aeson
import Servant.Server (Handler, ServerError)
import qualified Servant.Server as Servant
import Sthenauth.API.Log
import Sthenauth.API.Middleware (Client)
import Sthenauth.Core.Error (Sterr(..), UserError(..))
import Sthenauth.Effect (setCurrentUser)
import Sthenauth.Effect.Carrier (SthenauthC, Environment, runSthenauth)

--------------------------------------------------------------------------------
-- | A type of effect that can use Sthenauth and Throw.
type Action = SthenauthC (ErrorC Sterr (LiftC Handler))

--------------------------------------------------------------------------------
-- | Execute a 'Sthenauth' action, producing a Servant @Handler@.
runRequest
  :: forall a.
  Environment
  -> Client
  -> Logger
  -> Action a
  -> Handler a
runRequest env client log orig =
  runSthenauth env (fst client) action
    & runError
    & runM
    >>= either onError pure
  where
    action :: Action a
    action = do
      traverse_ setCurrentUser (client ^. _2)
      orig

    onError :: Sterr -> Handler a
    onError e = do
      liftIO (logger_error log (fst client) (show e :: Text))
      CME.throwError (toServerError e)

--------------------------------------------------------------------------------
toServerError :: Sterr -> ServerError
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
