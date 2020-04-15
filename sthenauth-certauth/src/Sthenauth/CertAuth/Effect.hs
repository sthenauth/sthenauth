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

A class of monads that can act like a certificate authority.

-}
module Sthenauth.CertAuth.Effect
  ( CertAuth(..)
  , ServerCreds
  , fetchServerCredentials

    -- * Re-exports
  , Algebra
  , Effect
  , Has
  , run
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Data.Time.Clock (UTCTime)
import qualified Data.X509 as X509
import GHC.Generics (Generic1)

--------------------------------------------------------------------------------
-- | A certificate chain, the leaf certificate's private key, and the
-- earliest time that any certificate in the chain will expire.
type ServerCreds = (UTCTime, X509.CertificateChain, X509.PrivKey)

--------------------------------------------------------------------------------
-- | Certificate authority algebra.
newtype CertAuth m k
  = FetchServerCredentials (ServerCreds -> m k)
  deriving stock (Generic1, Functor)
  deriving anyclass (HFunctor, Effect)

--------------------------------------------------------------------------------
-- | Fetch (or create) server credentials for the internal web server.
fetchServerCredentials :: Has CertAuth sig m => m ServerCreds
fetchServerCredentials = send (FetchServerCredentials pure)
