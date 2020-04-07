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
module Sthenauth.Core.Crypto
  ( Crypto(..)
  , ToSafe(..)
  , encrypt
  , decrypt
  , toSaltedHash
  , toHashedSecret
  , generatePassword
  , toHashedPassword
  , verifyPassword
  , generateSaltSized
  , randomByteArray
  , throwCryptoError

  , CryptoC
  , Runtime
  , initCrypto
  , getCryptonite
  , runCrypto

    -- * Re-exports
  , Password
  , Hashed
  , Clear
  , Strong
  , Secret
  , HashedSecret
  , SaltedHash
  , MonadRandom
  , Algebra
  , Effect
  , Has
  , run
  ) where

--------------------------------------------------------------------------------
import Control.Algebra
import Control.Carrier.Reader
import Control.Lens (views, makeLenses)
import Control.Monad.Crypto.Class (MonadCrypto)
import qualified Control.Monad.Crypto.Cryptonite as Crypto
import Control.Monad.Error.Lens (throwing)
import Control.Monad.Except (MonadError, runExceptT)
import Crypto.Random (MonadRandom, getRandomBytes)
import qualified Data.Aeson as Aeson
import Data.Binary (Binary)
import Data.ByteArray (ByteArray)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Traversable (for)
import Iolaus.Crypto.Error
import Iolaus.Crypto.HashedSecret (HashedSecret)
import qualified Iolaus.Crypto.HashedSecret as Crypto
import Iolaus.Crypto.Password (Password, Clear, Strong, Hashed, VerifyStatus)
import qualified Iolaus.Crypto.Password as Crypto
import Iolaus.Crypto.Salt (Salt, SharedSalt(..))
import qualified Iolaus.Crypto.Salt as Crypto
import Iolaus.Crypto.SaltedHash (SaltedHash, ForSaltedHash)
import Iolaus.Crypto.Secret (Secret)
import Sthenauth.Core.Error

import Control.Monad.Crypto.Cryptonite
  ( KeyManager(..)
  , GetStatus(..)
  , PutStatus(..)
  , FileExtension(..)
  , Cryptonite
  , CryptoniteT
  )

--------------------------------------------------------------------------------
-- | A simple cryptography effect.
data Crypto m k
  = forall a. Binary a => Encrypt a (Secret a -> m k)
  | forall a. Binary a => Decrypt (Secret a) (a -> m k)
  | forall a. ForSaltedHash a => ToSaltedHash a (SaltedHash a -> m k)
  | forall a. (ForSaltedHash a, Binary a) => ToHashedSecret a (HashedSecret a -> m k)
  | GeneratePassword ((Text, Password Hashed) -> m k)
  | ToHashedPassword (Password Strong) (Password Hashed -> m k)
  | VerifyPassword (Password Clear) (Password Hashed) (VerifyStatus -> m k)
  | GenerateSaltSized Int (Salt -> m k)
  | forall a. ByteArray a => RandomByteArray Int (a -> m k)

deriving instance Functor m => Functor (Crypto m)

instance HFunctor Crypto where
  hmap f = \case
    Encrypt a k -> Encrypt a (f . k)
    Decrypt a k -> Decrypt a (f . k)
    ToSaltedHash a k -> ToSaltedHash a (f . k)
    ToHashedSecret a k -> ToHashedSecret a (f . k)
    GeneratePassword k -> GeneratePassword (f . k)
    ToHashedPassword a k -> ToHashedPassword a (f . k)
    VerifyPassword pc ph k -> VerifyPassword pc ph (f . k)
    GenerateSaltSized n k -> GenerateSaltSized n (f . k)
    RandomByteArray n k -> RandomByteArray n (f . k)

instance Effect Crypto where
  thread ctx handler = \case
    Encrypt a k -> Encrypt a (handler . (<$ ctx) . k)
    Decrypt a k -> Decrypt a (handler . (<$ ctx) . k)
    ToSaltedHash a k -> ToSaltedHash a (handler . (<$ ctx) . k)
    ToHashedSecret a k -> ToHashedSecret a (handler . (<$ ctx) . k)
    GeneratePassword k -> GeneratePassword (handler . (<$ ctx) . k)
    ToHashedPassword a k -> ToHashedPassword a (handler . (<$ ctx) . k)
    VerifyPassword pc ph k -> VerifyPassword pc ph (handler . (<$ ctx) . k)
    GenerateSaltSized n k -> GenerateSaltSized n (handler . (<$ ctx) . k)
    RandomByteArray n k -> RandomByteArray n (handler . (<$ ctx) . k)

--------------------------------------------------------------------------------
-- | Encrypt a value with the active symmetric key.
encrypt :: (Has Crypto sig m, Binary a) => a -> m (Secret a)
encrypt = send . (`Encrypt` pure)

--------------------------------------------------------------------------------
-- | Decrypt a value.
--
-- If decryption fails the next available key is tried.  If all keys
-- fail an error is thrown.
decrypt :: (Has Crypto sig m, Binary a) => Secret a -> m a
decrypt = send . (`Decrypt` pure)

--------------------------------------------------------------------------------
toSaltedHash :: (Has Crypto sig m, ForSaltedHash a) => a -> m (SaltedHash a)
toSaltedHash = send . (`ToSaltedHash` pure)

--------------------------------------------------------------------------------
toHashedSecret :: (Has Crypto sig m, ForSaltedHash a, Binary a) => a -> m (HashedSecret a)
toHashedSecret = send . (`ToHashedSecret` pure)

--------------------------------------------------------------------------------
generatePassword :: Has Crypto sig m => m (Text, Password Hashed)
generatePassword = send (GeneratePassword pure)

--------------------------------------------------------------------------------
toHashedPassword :: Has Crypto sig m => Password Strong -> m (Password Hashed)
toHashedPassword = send . (`ToHashedPassword` pure)

--------------------------------------------------------------------------------
verifyPassword :: Has Crypto sig m => Password Clear -> Password Hashed -> m VerifyStatus
verifyPassword pc ph = send (VerifyPassword pc ph pure)

--------------------------------------------------------------------------------
generateSaltSized :: Has Crypto sig m => Int -> m Salt
generateSaltSized = send . (`GenerateSaltSized` pure)

--------------------------------------------------------------------------------
randomByteArray :: (Has Crypto sig m, ByteArray a) => Int -> m a
randomByteArray = send . (`RandomByteArray` pure)

--------------------------------------------------------------------------------
throwCryptoError :: Has (Throw Sterr) sig m => CryptoError -> m a
throwCryptoError = throwError . BaseCryptoError

--------------------------------------------------------------------------------
-- | Types that can be encrypted or hashed.
class ToSafe a where
  type SafeT a
  toSafe :: Has Crypto sig m => a -> m (SafeT a)

--------------------------------------------------------------------------------
data Keys = Keys
  { _systemSalts :: NonEmpty SharedSalt
    -- ^ System-wide salt.

  , _symmetricKeys :: NonEmpty (Crypto.Key Cryptonite)
    -- ^ Symmetric encryption key.

  } deriving (Generic)

makeLenses ''Keys

--------------------------------------------------------------------------------
newtype Runtime = Runtime (Cryptonite, Keys)

--------------------------------------------------------------------------------
newtype CryptoC m a = CryptoC
  { runCryptoC :: ReaderC Runtime m a }
  deriving newtype (Functor, Applicative, Monad, MonadIO, MonadTrans)

--------------------------------------------------------------------------------
liftCrypto :: Has (Throw Sterr) sig m => CryptoniteT m a -> CryptoC m a
liftCrypto c = CryptoC $ do
  Runtime (env, _) <- ask
  lift (Crypto.runCryptoniteT env c) >>= \case
    Left e  -> throwError (BaseCryptoError e)
    Right a -> pure a

--------------------------------------------------------------------------------
instance ( MonadIO m
         , Has (Throw Sterr) sig m
         , Algebra sig m
         )
  => Algebra (Crypto :+: sig) (CryptoC m) where
  alg op = do
    Runtime (_, keys) <- CryptoC ask
    case op of
      R other -> CryptoC (alg (R (handleCoercible other)))
      L (Encrypt a k) ->
        let key = keys & views symmetricKeys NonEmpty.head
        in liftCrypto (Crypto.encryptBinary key a) >>= k
      L (Decrypt s k) ->
        let keyList = keys & views symmetricKeys NonEmpty.toList
        in liftCrypto (Crypto.tryDecryptBinary keyList s) >>= \case
              Nothing -> throwError (BaseCryptoError MalformedCipherTextError)
              Just a  -> k a
      L (ToSaltedHash a k) ->
        let salt = keys & views systemSalts NonEmpty.head
        in k (Crypto.saltedHash salt a)
      L (ToHashedSecret a k) ->
        let salt = keys & views systemSalts NonEmpty.head
            key  = keys & views symmetricKeys NonEmpty.head
        in liftCrypto (Crypto.toHashedSecret key salt a) >>= k
      L (GeneratePassword k) ->
        let salt = keys & views systemSalts NonEmpty.head
        in liftCrypto (Crypto.generatePassword salt Crypto.defaultSettings) >>= k
      L (ToHashedPassword p k) ->
        let salt = keys & views systemSalts NonEmpty.head
        in liftCrypto (Crypto.toHashedPassword salt Crypto.defaultSettings p) >>= k
      L (VerifyPassword pc ph k) ->
        let salt = keys & views systemSalts NonEmpty.head
        in k (Crypto.verifyPassword salt Crypto.defaultSettings pc ph)
      L (GenerateSaltSized n k) -> liftCrypto (Crypto.generateSalt' n) >>= k
      L (RandomByteArray n k) -> liftCrypto (getRandomBytes n) >>= k

--------------------------------------------------------------------------------
-- | Load secrets from disk, generating those that are missing.
initCrypto
  :: MonadIO m
  => Cryptonite
  -> NonEmpty Text
     -- ^ Names of encryption keys.
  -> NonEmpty Text
     -- ^ Names of system salts.
  -> KeyManager
     -- ^ A key manager were salt can be stored.
  -> m (Either Sterr Runtime)
initCrypto crypto keys salts mgr =
    Crypto.runCryptoniteT crypto (runExceptT mkKeys) >>= \case
      Left e -> pure (Left (BaseCryptoError e))
      Right a -> pure (fmap (Runtime . (crypto,)) a)

  where
    mkKeys
      :: ( MonadIO m
         , MonadCrypto Cryptonite m
         , MonadError Sterr m
         ) => m Keys
    mkKeys = do
      _symmetricKeys <- for keys $ \name -> do
          let label = Crypto.toLabel name
          key <- Crypto.fetchKey label
          maybe (Crypto.generateKey Crypto.AES256 label) return key

      _systemSalts <- for salts $ \name -> do
          let label = Crypto.toLabel name
              ext   = OtherExt "salt"
          fmap toSalt (liftIO (managerGetKey mgr label ext)) >>= \case
            Just s -> return (SharedSalt s)
            Nothing -> do
              salt <- Crypto.generateSalt
              let bs = toStrict (Aeson.encode salt)
              liftIO (managerPutKey mgr label ext bs) >>= \case
                PutSucceeded -> return (SharedSalt salt)
                PutKeyExists -> throwing _RuntimeError "impossible: key can't exist here"
                PutFailed    -> throwing _RuntimeError "failed to write salt to disk"
      pure Keys{..}

    toSalt :: GetStatus -> Maybe Salt
    toSalt (GetSucceeded bs) = Aeson.decode (toLazy bs)
    toSalt GetFailed         = Nothing

--------------------------------------------------------------------------------
getCryptonite :: Runtime -> Cryptonite
getCryptonite (Runtime (c, _)) = c

--------------------------------------------------------------------------------
runCrypto :: Runtime -> CryptoC m a -> m a
runCrypto e = runReader e . runCryptoC
