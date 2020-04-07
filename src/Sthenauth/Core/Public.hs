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

Public versions of some existing types.

-}
module Sthenauth.Core.Public
  ( Session(..)
  , toSession
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Data.Aeson as Aeson
import Data.Time.Clock (UTCTime(..))
import qualified Generics.SOP as SOP
import Sthenauth.Core.Encoding
import qualified Sthenauth.Core.Session as Session

--------------------------------------------------------------------------------
data Session = Session
  { sessionExpiresAt  :: UTCTime
  , sessionInactiveAt :: UTCTime
  , sessionCreatedAt  :: UTCTime
  , sessionUpdatedAt  :: UTCTime
  }
  deriving stock (Generic, Show)
  deriving anyclass (SOP.Generic, SOP.HasDatatypeInfo)
  deriving (ToJSON, FromJSON) via GenericJSON Session
  deriving ( HasElmType
           , HasElmEncoder Aeson.Value
           , HasElmDecoder Aeson.Value
           ) via GenericElm "Session" Session

--------------------------------------------------------------------------------
toSession :: Session.Session -> Session
toSession session =
  Session
    { sessionExpiresAt  = Session.sessionExpiresAt session
    , sessionInactiveAt = Session.sessionInactiveAt session
    , sessionCreatedAt  = Session.sessionCreatedAt session
    , sessionUpdatedAt  = Session.sessionUpdatedAt session
    }
