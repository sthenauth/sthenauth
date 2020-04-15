{-# LANGUAGE Arrows #-}

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
module Sthenauth.CertAuth.Certificate
  ( CertificateF(..)
  , Certificate
  , CertId
  , CertUse(..)
  , SqlCertUse
  , certId
  , toCertChain
  , toSignedCert
  , selectActiveCert
  , rootCert
  , intermediateCert
  , selectChain
  , insertCert
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Arrow (returnA)
import Control.Lens ((^.), _3)
import Data.List (minimumBy)
import Data.PEM (pemContent)
import Data.Profunctor (dimap)
import Data.Profunctor.Product.Default (Default(..))
import Data.Time.Clock (UTCTime)
import qualified Data.X509 as X509
import Iolaus.Crypto.PEM (decodePEM)
import Iolaus.Database.Extra (transactionTimestamp)
import Iolaus.Database.Query
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.Core.Encoding

import Database.PostgreSQL.Simple.FromField
  ( FromField(..)
  , ResultError(..)
  , returnError
  )

import Opaleye
  ( QueryRunnerColumnDefault
  , Constant
  , Column
  )

--------------------------------------------------------------------------------
type CertId = Key UUID CertificateF

--------------------------------------------------------------------------------
certId :: UUID -> CertId
certId = Key

--------------------------------------------------------------------------------
-- | Flag indicating how a certificate will be used.
data CertUse
  = RootCert
  | IntermediateCert
  | LocalhostCert
  | ClientCert
  deriving stock (Generic, Show, Eq, Ord)
  deriving (ToJSON, FromJSON) via GenericJSON CertUse

--------------------------------------------------------------------------------
-- | For table definitions:
data SqlCertUse

--------------------------------------------------------------------------------
fromCertUse :: CertUse -> Text
fromCertUse = \case
  RootCert -> "root"
  IntermediateCert -> "intermediate"
  LocalhostCert -> "localhost"
  ClientCert -> "client"

--------------------------------------------------------------------------------
toCertUse :: (MonadPlus m) => Text -> m CertUse
toCertUse = \case
  "root"         -> pure RootCert
  "intermediate" -> pure IntermediateCert
  "localhost"    -> pure LocalhostCert
  "client"       -> pure ClientCert
  _              -> mzero

--------------------------------------------------------------------------------
instance FromField CertUse where
  fromField f mdata =
    case mdata of
      Just bs -> toCertUse (decodeUtf8 bs)
      Nothing -> returnError ConversionFailed f "Unexpected empty value"

instance QueryRunnerColumnDefault SqlCertUse CertUse where
  queryRunnerColumnDefault = O.fieldQueryRunnerColumn

instance Default Constant CertUse (Column SqlCertUse) where
  def = dimap fromCertUse (O.unsafeCast "cert_use_t") def_
    where def_ :: Constant Text (Column SqlText)
          def_ = def

--------------------------------------------------------------------------------
-- | The @certificates@ table.
data CertificateF f = Certificate
  { pk :: Col f "id" CertId SqlUuid Required
    -- ^ Primary key and the certificate's serial number.

  , parentId :: Col f "parent_id" CertId SqlUuid Nullable
    -- ^ Parent certificate.

  , certUse :: Col f "cert_use" CertUse SqlCertUse Required
    -- ^ How is this certificate used?

  , certPem :: Col f "cert_pem" ByteString SqlBytea Required
    -- ^ The encoded certificate.

  , expiresAt :: Col f "expires_at" UTCTime SqlTimestamptz Required
    -- ^ The time this certificate will expire and no longer be valid.

  , createdAt :: Col f "created_at" UTCTime SqlTimestamptz ReadOnly
    -- ^ The time this record was created.

  }

makeTable ''CertificateF "certificates"

--------------------------------------------------------------------------------
-- | Monomorphic certificate.
type Certificate = CertificateF ForHask

--------------------------------------------------------------------------------
-- | Given a list of certificates (leaf first, root last), generate
-- information about the chain.
toCertChain :: [Certificate] -> Maybe (UTCTime, CertId, X509.CertificateChain)
toCertChain [] = Nothing
toCertChain cs = (soonest,,) <$> leafId <*> chain
  where
    sorted :: [Certificate]
    sorted = sortOn certUse cs

    soonest :: UTCTime
    soonest = expiresAt (minimumBy (comparing expiresAt) sorted)

    leafId :: Maybe CertId
    leafId = case sorted of
      [_, _, l] -> Just (pk l)
      _         -> Nothing

    chain :: Maybe X509.CertificateChain
    chain = X509.CertificateChain <$> traverse toSignedCert cs

--------------------------------------------------------------------------------
-- | Extract a signed certificate from a 'Certificate' record.
toSignedCert :: Certificate -> Maybe X509.SignedCertificate
toSignedCert Certificate{certPem} = do
  pem <- listToMaybe (decodePEM (toLazy certPem))
  rightToMaybe (X509.decodeSignedCertificate (pemContent pem))

--------------------------------------------------------------------------------
-- | Modify the given query so that it returns the newest certificate
-- that is still active.
selectActiveCert :: SelectArr (CertificateF SqlRead) (CertificateF SqlRead)
                 -> Select    (CertificateF SqlRead)
selectActiveCert other = O.orderBy (O.desc expiresAt) (O.limit 1 query)
  where
    query = proc () -> do
      certs <- O.selectTable certificates -< ()
      O.restrict -< (expiresAt certs .> transactionTimestamp)
      other -< certs

--------------------------------------------------------------------------------
-- | Select only root certificates.
rootCert :: SelectArr (CertificateF SqlRead) (CertificateF SqlRead)
rootCert = proc certs -> do
  O.restrict -< (certUse certs .== toFields RootCert)
  returnA -< certs

--------------------------------------------------------------------------------
-- | Select only intermediate certificates whose parent is the given
-- certificate.
intermediateCert
  :: Certificate
  -> SelectArr (CertificateF SqlRead) (CertificateF SqlRead)
intermediateCert root = proc certs -> do
  O.restrict -< (certUse certs .== toFields IntermediateCert .&&
                 parentId certs .== O.toNullable (toFields (pk root)))
  returnA -< certs

--------------------------------------------------------------------------------
-- Select a certificate chain whose leaf certificate has the given
-- 'CertUse' flag.
selectChain
  :: CertUse
  -> Select ( CertificateF SqlRead -- Leaf
            , CertificateF SqlRead -- Intermediate
            , CertificateF SqlRead -- Root
            )
selectChain leafUse =
    O.orderBy (O.desc (expiresAt . (^. _3))) go
  where
    go = proc () -> do
      t1 <- selectTable certificates -< ()
      t2 <- selectTable certificates -< ()
      t3 <- selectTable certificates -< ()

      O.restrict -< (
        certUse t1 .== toFields RootCert .&&
        expiresAt t1 .> transactionTimestamp .&&
        certUse t2 .== toFields IntermediateCert .&&
        expiresAt t2 .> transactionTimestamp .&&
        parentId t2 .== O.toNullable (pk t1) .&&
        expiresAt t3 .> transactionTimestamp .&&
        parentId t3 .== O.toNullable (pk t2)) .&&
        certUse t3 .== toFields leafUse

      returnA -< (t3, t2, t1)

--------------------------------------------------------------------------------
-- | Insert a certificate into the database.
insertCert :: CertificateF SqlWrite -> Query (Maybe Certificate)
insertCert cert = listToMaybe <$> insert ins
  where
    ins :: Insert [Certificate]
    ins =  Insert certificates [cert] (rReturning id) Nothing
