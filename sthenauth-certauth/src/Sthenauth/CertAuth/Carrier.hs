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
module Sthenauth.CertAuth.Carrier
  ( CertAuthC
  , CertAuthEnv
  , initCertAuth
  , runCertAuth
  , module Sthenauth.CertAuth.Effect
  ) where

--------------------------------------------------------------------------------
-- FIXME: Expire certificates from the database.
-- FIXME: Garbage collect keys for certificates that no longer exist.
-- FIXME: Renew certificates.

--------------------------------------------------------------------------------
-- Imports:
import Control.Algebra
import Control.Carrier.Reader
import Control.Lens.TH (makeLenses)
import Control.Monad.Crypto.Cryptonite
import Data.List (minimumBy)
import Data.Time.Calendar (addGregorianMonthsRollOver)
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import qualified Data.X509 as X509
import Iolaus.Crypto.PEM
import Iolaus.Crypto.X509
import Iolaus.Database.Query (SelectArr, select1, toFields)
import Iolaus.Database.Table
import qualified Opaleye as O
import Sthenauth.CertAuth.Config
import Sthenauth.CertAuth.Effect
import Sthenauth.Core.Certificate
import Sthenauth.Core.Error
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import System.Random (randomIO)

--------------------------------------------------------------------------------
-- | The type of crypto (software/hardware) that the root certificate uses.
type RootCrypto = Cryptonite

--------------------------------------------------------------------------------
data SignWith
  = SignWithRootCert Certificate
  | SignWithRootKey (KeyPair RootCrypto)
  | SignWithIntermediateCert Certificate

--------------------------------------------------------------------------------
-- | Information about a certificate's common name.
data CommonName
  = RootName
  | IntermediateName
  | LocalhostName
  | ClientName Text
  deriving (Eq, Ord, Show)

--------------------------------------------------------------------------------
-- | Convert a common name to a certificate use flag.
commonNameToCertUse :: CommonName -> CertUse
commonNameToCertUse = \case
  RootName         -> RootCert
  IntermediateName -> IntermediateCert
  LocalhostName    -> LocalhostCert
  ClientName _     -> ClientCert

--------------------------------------------------------------------------------
-- | Runtime environment for the certificate authority.
data CertAuthEnv = CertAuthEnv
  { _envConfig     :: CertAuthConfig -- ^ Configuration.
  , _envSoftCrypto :: Cryptonite     -- ^ Cryptonite runtime for the Root env.
  }

makeLenses ''CertAuthEnv

--------------------------------------------------------------------------------
newtype CertAuthC m a = CertAuthC
  { runCertAuthC :: ReaderC CertAuthEnv m a }
  deriving newtype (Functor, Applicative, Monad, MonadIO, MonadTrans)

--------------------------------------------------------------------------------
type CertAuthDeps sig m
  = ( MonadIO m
    , Has Database sig m
    , Has Error    sig m
    )

--------------------------------------------------------------------------------
instance CertAuthDeps sig m => Algebra (CertAuth :+: sig) (CertAuthC m) where
  alg = \case
    R other -> CertAuthC (alg (R (handleCoercible other)))
    L (FetchServerCredentials next) -> findOrCreateServerCreds >>= next

--------------------------------------------------------------------------------
-- | Find/create a TLS certificate chain.
findOrCreateServerCreds
  :: (MonadIO m, Has Database sig m, Has Error sig m)
  => CertAuthC m ServerCreds
findOrCreateServerCreds =
  runQuery (select1 (selectChain LocalhostCert)) >>= \case
    Nothing -> createCertificateForLocalhost
    Just (lc, ic, rc) -> do
      (expire, _, chain) <- maybe die pure (toCertChain [lc, ic, rc])
      crypto <- CertAuthC (asks (^. envSoftCrypto))
      withIntermediateCrypto crypto (fetchKeyPair (labelFromCert lc)) >>= \case
        Nothing  -> die
        Just key -> (expire, chain,) <$>
          withIntermediateCrypto crypto (toX509PrivKey key)
  where
    die = throwError (RuntimeError "certificate authority failed")

--------------------------------------------------------------------------------
-- | Create a leaf TLS certificate for a web server and return the
-- certificate chain.
createCertificateForLocalhost
  :: ( MonadIO          m
     , Has Database sig m
     , Has Error    sig m
     )
  => CertAuthC m ServerCreds
createCertificateForLocalhost = do
  env           <- CertAuthC ask
  uuid          <- liftIO randomIO
  (root, inter) <- findOrCreateIntermediateCert env
  (pub, priv)   <- generateLeafKeyPair env (labelFromUUID uuid)
  range         <- calcCertTimeRange env LocalhostCert

  let interSign cert = signCertWith env cert (SignWithIntermediateCert inter)
      forTLS = certForTLS (Server "localhost")

  cert <- createAndSignCert
            env uuid range LocalhostName (Just inter)
            pub forTLS interSign >>= writeCertToDb

  let chain  = [cert, inter, root]
      expire = expiresAt (minimumBy (comparing expiresAt) chain)

  case X509.CertificateChain <$> traverse toSignedCert chain of
    Nothing -> throwError (RuntimeError "impossible chain encoding error")
    Just xchain -> pure (expire, xchain, priv)

--------------------------------------------------------------------------------
-- | Run a crypto operation inside the root environment.
withRootCrypto
  :: (MonadIO m, Has Error sig m)
  => Cryptonite -> CryptoniteT m a -> m a
withRootCrypto crypto n =
  runCryptoniteT crypto n >>= \case
    Left e  -> throwError (BaseCryptoError e)
    Right a -> return a

--------------------------------------------------------------------------------
-- | Runa crypto operation inside the intermediate environment.
--
-- NOTE: For now this is just an alias for the root environment.
withIntermediateCrypto
  :: (MonadIO m, Has Error sig m)
  => Cryptonite -> CryptoniteT m a -> m a
withIntermediateCrypto = withRootCrypto

--------------------------------------------------------------------------------
generateLeafKeyPair
  :: (MonadIO m, Has Error sig m)
  => CertAuthEnv -> Label -> m (PublicKey, X509.PrivKey)
generateLeafKeyPair env label =
  withIntermediateCrypto (env ^. envSoftCrypto) $ do
      key  <- generateKeyPair (env ^. envConfig.certAlgo) label
      priv <- toX509PrivKey key
      pub  <- toPublicKey key
      pure (pub, priv)

--------------------------------------------------------------------------------
signCertWith
  :: (MonadIO m, Has Error sig m)
  => CertAuthEnv ->  X509.Certificate -> SignWith -> m X509.SignedCertificate
signCertWith env cert = \case
    SignWithRootKey key ->
      withRootCrypto crypto (signCert key cert)
    SignWithRootCert root ->
      let label = labelFromCert root
      in withRootCrypto crypto (fetchSign label) >>= checkSign label
    SignWithIntermediateCert inter ->
      let label = labelFromCert inter
      in withIntermediateCrypto crypto (fetchSign label) >>= checkSign label
  where
    crypto = env ^. envSoftCrypto
    fetchSign label = fetchKeyPair label >>= traverse (`signCert` cert)
    checkSign label = maybe (die label) pure
    die = throwCryptoError . KeyDoesNotExistError . getLabelText

--------------------------------------------------------------------------------
-- | Helper function to find a certificate in the database, or if one
-- can't be found, create a new one.
findOrCreateCaCert
  :: ( MonadIO          m
     , Has Database sig m
     , Has Error    sig m
     )
  => CertAuthEnv

  -> CertUse
     -- ^ The type of certificate.

  -> SelectArr (CertificateF SqlRead) (CertificateF SqlRead)
     -- ^ A database query that can find the certificate
     -- This query is passed to 'selectActiveCert'.

  -> (UUID -> (UTCTime, UTCTime) -> m Certificate)
     -- A function that can generate a certificate.

  -> m Certificate
     -- ^ The fetched or generated certificate.

findOrCreateCaCert env certUse query gen =
  runQuery (select1 $ selectActiveCert query) >>= \case
    Just cert -> pure cert
    Nothing -> do
      uuid  <- liftIO randomIO
      range <- calcCertTimeRange env certUse
      gen uuid range

--------------------------------------------------------------------------------
-- | Find the active root certificate or create a new one.
findOrCreateRootCert
  :: ( MonadIO          m
     , Has Database sig m
     , Has Error    sig m
     )
  => CertAuthEnv -> m Certificate
findOrCreateRootCert env =
  findOrCreateCaCert env RootCert
    rootCert (createRootCert env)

--------------------------------------------------------------------------------
-- | Find the active intermediate certificate or create a new one.
findOrCreateIntermediateCert
  :: ( MonadIO          m
     , Has Database sig m
     , Has Error    sig m
     )
  => CertAuthEnv -> m (Certificate, Certificate)
findOrCreateIntermediateCert env = do
  root <- findOrCreateRootCert env
  (root,) <$> findOrCreateCaCert env IntermediateCert
                (intermediateCert root)
                (createIntermediateCert env root)

--------------------------------------------------------------------------------
-- | Helper function for generating and signing certificates.
createAndSignCert
  :: Monad m

  => CertAuthEnv

  -> UUID
     -- ^ The UUID of the new certificate.

  -> (UTCTime, UTCTime)
    -- ^ Validity time range.

  -> CommonName
     -- ^ The purpose and name of the new certificate.

  -> Maybe Certificate
    -- ^ Optional parent certificate.

  -> PublicKey
    -- ^ The public key to associate with the certificate.

  -> (X509.Certificate -> X509.Certificate)
     -- ^ A function that can modify the generated certificate.

  -> (X509.Certificate -> m X509.SignedCertificate)
     -- ^ Function to sign the certificate.

  -> m (CertificateF SqlWrite)
     -- ^ The certificate saved in the database.

createAndSignCert env uuid range' cn parent pub modF signF = do
    let range      = limitRange parent range'
        parentCert = parent >>= toSignedCert
        commonName = prepareCommonName env cn
        algo       = env ^. envConfig.certAlgo
        hash       = env ^. envConfig.certHash

    let cert = modF (makeCert uuid commonName algo hash parentCert range pub)
    signed <- signF cert

    pure Certificate
      { pk        = toFields uuid
      , parentId  = O.maybeToNullable (toFields . pk <$> parent)
      , certUse   = toFields (commonNameToCertUse cn)
      , certPem   = toFields $ toStrict (encodePEM [encodeSignedCert signed])
      , expiresAt = toFields (range ^. _2)
      , createdAt = Nothing
      }

  where
    -- The expiration time for the new cert can't exceed its parent.
    limitRange :: Maybe Certificate
               -> (UTCTime, UTCTime)
               -> (UTCTime, UTCTime)
    limitRange = \case
      Nothing -> id
      Just p  -> over _2 (min (expiresAt p))

--------------------------------------------------------------------------------
-- | Create a self-signed root certificate and save it to the database.
createRootCert
  :: ( MonadIO          m
     , Has Database sig m
     , Has Error    sig m
     )
  => CertAuthEnv
  -> UUID               -- ^ The UUID to use.
  -> (UTCTime, UTCTime) -- ^ Time range
  -> m Certificate      -- ^ The new certificate.
createRootCert env uuid range = do
  (key, pub) <- withRootCrypto
                  (env ^. envSoftCrypto)
                  (genKeys (env ^. envConfig.certAlgo) uuid)

  let forCA      = certForCA (PathLenConstraint (Just 2))
      selfSign c = signCertWith env c (SignWithRootKey key)

  createAndSignCert
    env uuid range RootName Nothing
    pub forCA selfSign >>= writeCertToDb

--------------------------------------------------------------------------------
-- | Create an intermediate certificate, signed by the root
-- certificate, and save it to the database.
createIntermediateCert
  :: ( MonadIO          m
     , Has Database sig m
     , Has Error    sig m
     )
  => CertAuthEnv
  -> Certificate   -- ^ The root certificate
  -> UUID          -- ^ The UUID to use.
  -> (UTCTime, UTCTime) -- ^ Time range.
  -> m Certificate -- ^ The new certificate.
createIntermediateCert env root uuid range = do
  (_, pub) <- withIntermediateCrypto
                (env ^. envSoftCrypto)
                (genKeys (env ^. envConfig.certAlgo) uuid)

  let forCA      = certForCA (PathLenConstraint (Just 2))
      rootSign c = signCertWith env c (SignWithRootCert root)

  createAndSignCert
    env uuid range IntermediateName (Just root)
    pub forCA rootSign >>= writeCertToDb

--------------------------------------------------------------------------------
-- | Write a certificate into the database.  Throws an error on failure.
writeCertToDb
  :: ( Has Database sig m
     , Has Error    sig m
     )
  => CertificateF SqlWrite
  -> m Certificate
writeCertToDb = runQuery . insertCert >=> \case
  Just r  -> return r
  Nothing -> throwError (RuntimeError "CertAuth: database write failed for a cert")

--------------------------------------------------------------------------------
genKeys :: MonadCrypto k m => Algo -> UUID -> m (KeyPair k, PublicKey)
genKeys algo uuid = do
  key <- generateKeyPair algo (labelFromUUID uuid)
  pub <- toPublicKey key
  pure (key, pub)

--------------------------------------------------------------------------------
calcCertTimeRange :: MonadIO m => CertAuthEnv -> CertUse -> m (UTCTime, UTCTime)
calcCertTimeRange env certUse = do
    start <- liftIO getCurrentTime
    pure (makeTimeRange (months certUse) start)
  where
    months = \case
      RootCert         -> env ^. envConfig.lifespan.rootCertMaxAgeMonths
      IntermediateCert -> env ^. envConfig.lifespan.intermediateCertMaxAgeMonths
      LocalhostCert    -> env ^. envConfig.lifespan.leafCertMaxAgeMonths
      ClientCert       -> env ^. envConfig.lifespan.leafCertMaxAgeMonths

--------------------------------------------------------------------------------
-- | Add the given number of months to a 'UTCTime' to make a validity
-- range for X509 certificates.
makeTimeRange :: Natural -> UTCTime -> (UTCTime, UTCTime)
makeTimeRange months start =
  let add = addGregorianMonthsRollOver (fromIntegral months) . utctDay
  in (start, start { utctDay = add start })

--------------------------------------------------------------------------------
prepareCommonName :: CertAuthEnv -> CommonName -> Text
prepareCommonName env = \case
    RootName -> (prefix <> " Root")
    IntermediateName -> (prefix <> " Intermediate")
    LocalhostName -> "localhost"
    ClientName n -> n
  where
    prefix = env ^. envConfig.commonNamePrefix

--------------------------------------------------------------------------------
-- | Create a key label for the given certificate UUID.
labelFromUUID :: UUID -> Label
labelFromUUID = toLabel . ("Certificate " <>) . UUID.toText

--------------------------------------------------------------------------------
labelFromCert :: Certificate -> Label
labelFromCert = labelFromUUID . getKey . pk

--------------------------------------------------------------------------------
-- | Create the run-time environment needed by 'runCertAuthT'.
initCertAuth
  :: CertAuthConfig
  -> Cryptonite
  -> CertAuthEnv
initCertAuth = CertAuthEnv

--------------------------------------------------------------------------------
-- | Discharge the 'MonadCertAuth' constraint from an action.
runCertAuth
  :: CertAuthEnv
  -> CertAuthC m a
  -> m a
runCertAuth env app
  = runCertAuthC app
  & runReader env
