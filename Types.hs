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
module Sthenauth.Providers.Types
  ( ProviderResponse(..)
  , AdditionalAuthStep(..)
  , AccountStatus(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Data.Aeson as Aeson
import qualified Generics.SOP as SOP
import Sthenauth.Core.Account (Account)
import Sthenauth.Core.Encoding
import Sthenauth.Core.Error
import Sthenauth.Core.EventDetail
import Sthenauth.Core.URL
import Web.Cookie

--------------------------------------------------------------------------------
-- | How a provider can respond to a request.
data ProviderResponse
  = ProcessAdditionalStep AdditionalAuthStep (Maybe SetCookie)
    -- ^ Another step in the authentication process is required.

  | SuccessfulAuthN Account AccountStatus
    -- ^ The end-user has successfully authenticated.

  | SuccessfulLogout (Maybe SetCookie)
    -- ^ The end-user was successfully logged out.

  | FailedAuthN UserError EventDetail
    -- ^ The end-user failed authentication.

--------------------------------------------------------------------------------
newtype AdditionalAuthStep
  = RedirectTo URL
    -- ^ Send the end-user to the given URL, setting a cookie.

  deriving stock (Generic, Eq, Show)
  deriving anyclass (SOP.Generic, SOP.HasDatatypeInfo)
  deriving (ToJSON, FromJSON) via GenericJSON AdditionalAuthStep
  deriving ( HasElmType
           , HasElmDecoder Aeson.Value
           , HasElmEncoder Aeson.Value
           ) via GenericElm "AdditionalAuthStep" AdditionalAuthStep

--------------------------------------------------------------------------------
-- | The status of an account being returned from authentication.
data AccountStatus
  = NewAccount       -- ^ The account was just created.
  | ExistingAccount  -- ^ The account already existed.
