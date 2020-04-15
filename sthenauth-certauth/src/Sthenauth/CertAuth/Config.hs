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

Private certificate authority.

-}
module Sthenauth.CertAuth.Config
  ( CertAuthConfig(..)
  , Lifespan(..)
  , commonNamePrefix
  , certAlgo
  , certHash
  , lifespan
  , defaultCertAuthConfig
  , rootCertMaxAgeMonths
  , intermediateCertMaxAgeMonths
  , leafCertMaxAgeMonths
  , allowDatabaseMigration
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeLenses)
import Control.Monad.Crypto.Cryptonite
import Data.Aeson ((.:?), (.!=))
import qualified Data.Aeson as Aeson
import Sthenauth.Core.Encoding

--------------------------------------------------------------------------------
-- | Number of months that a certificate is valid.
data Lifespan = Lifespan
  { _rootCertMaxAgeMonths :: Natural
    -- ^ How long, in months, should a root certificate be active?

  , _intermediateCertMaxAgeMonths :: Natural
    -- ^ How long, in months, should an intermediate certificate be active?

  , _leafCertMaxAgeMonths :: Natural
    -- ^ How long, in months, should a leaf (site) certificate be active?
  }
  deriving (Generic)
  deriving (ToJSON) via GenericJSON Lifespan

makeLenses ''Lifespan

--------------------------------------------------------------------------------
-- | Default certificate lifespans.
defaultLifespan :: Lifespan
defaultLifespan = Lifespan
  { _rootCertMaxAgeMonths         = 60
  , _intermediateCertMaxAgeMonths = 12
  , _leafCertMaxAgeMonths         = 3
  }

instance FromJSON Lifespan where
  parseJSON = Aeson.withObject "CertAuth Lifespan" $ \v ->
    Lifespan
      <$> v .:? "root_cert_max_age_months" .!= _rootCertMaxAgeMonths
      <*> v .:? "intermediate_cert_max_age_months" .!= _intermediateCertMaxAgeMonths
      <*> v .:? "leaf_cert_max_age_months" .!= _leafCertMaxAgeMonths
    where
      Lifespan{..} = defaultLifespan

--------------------------------------------------------------------------------
-- | Certificate authority configuration.
data CertAuthConfig = CertAuthConfig
  { _commonNamePrefix :: Text
    -- ^ The common name used by the certificate authority.  Changing
    -- this will trigger the generation of new keys and certificates.

  , _certAlgo :: Algo
    -- ^ Which asymmetric algorithm to use for certs.

  , _certHash :: Hash
    -- ^ Which hashing algorithm to use for signing certificates.

  , _lifespan :: Lifespan
    -- ^ Details about how long certificates can be active.

  , _allowDatabaseMigration :: Bool
    -- ^ Can this instance of CertAuth run database migrations?
  }
  deriving (Generic)
  deriving (ToJSON) via GenericJSON CertAuthConfig

makeLenses ''CertAuthConfig

--------------------------------------------------------------------------------
-- | Default certificate authority configuration.
defaultCertAuthConfig :: CertAuthConfig
defaultCertAuthConfig =  CertAuthConfig
  { _commonNamePrefix       = "Sthenauth Certificate Authority"
  , _certAlgo               = RSA4096
  , _certHash               = SHA2_512
  , _lifespan               = defaultLifespan
  , _allowDatabaseMigration = True
  }

instance FromJSON CertAuthConfig where
  parseJSON = Aeson.withObject "CertAuth Config" $ \v ->
    CertAuthConfig
      <$> v .:? "common_name_prefix"       .!= _commonNamePrefix
      <*> v .:? "cert_algo"                .!= _certAlgo
      <*> v .:? "cert_hash"                .!= _certHash
      <*> v .:? "lifespan"                 .!= _lifespan
      <*> v .:? "allow_database_migration" .!= _allowDatabaseMigration
    where
      CertAuthConfig{..} = defaultCertAuthConfig
