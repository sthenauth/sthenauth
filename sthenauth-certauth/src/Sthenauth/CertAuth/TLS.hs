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

Provide TLS certificates for the internal web server.

-}
module Sthenauth.CertAuth.TLS
  ( serverSettingsForTLS
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Concurrent.MVar (modifyMVar)
import Control.Exception (throwIO)
import Control.Lens ((^.), _1, _2, _3)
import Data.Default.Class (def)
import Data.Time.Clock (getCurrentTime)
import qualified Data.X509 as X509
import Iolaus.Crypto.PEM
import Iolaus.Crypto.X509
import qualified Network.TLS as TLS
import qualified Network.Wai.Handler.WarpTLS as TLS
import Sthenauth.CertAuth.Carrier
import Sthenauth.Core.Error

--------------------------------------------------------------------------------
-- | Create the credentials structure needed by the TLS package.
serverCredsToTLSCredentials :: ServerCreds -> TLS.Credentials
serverCredsToTLSCredentials sc = TLS.Credentials [(sc ^. _2, sc ^. _3)]

--------------------------------------------------------------------------------
-- | Create TLS settings for the Warp web server which include an
-- auto-generated TLS certificate chain.
serverSettingsForTLS :: CertAuthEnv -> IO TLS.TLSSettings
serverSettingsForTLS env = do
    creds <- getCredentials
    var   <- newTVarIO $! creds
    sync  <- newMVar ()
    tls   <- initialCreds creds

    pure tls {
      TLS.tlsServerHooks =
        def { TLS.onServerNameIndication =
                \_ -> serverCredentials var sync
            }
    }
  where
    -- Called by the TLS library to get the correct certificate chain
    -- to use.  This function will use the currently cached chain as
    -- long as it hasn't expired.  Otherwise it will generate a new
    -- chain and start using that.
    serverCredentials :: TVar ServerCreds -> MVar () -> IO TLS.Credentials
    serverCredentials var sync = do
      now <- getCurrentTime
      mcreds <- atomically $ do
        creds <- readTVar var
        if creds ^. _1 > now
          then pure (Just creds)
          else pure Nothing
      case mcreds of
        Just c -> pure (serverCredsToTLSCredentials c)
        Nothing -> modifyMVar sync $ \() -> do
          creds <- getCredentials
          atomically (writeTVar var $! creds)
          pure ((), serverCredsToTLSCredentials creds)

    -- The initial TLS credentials that the server will offer.  These
    -- are only temporary since the SNI extension will trigger the
    -- 'serverCredentials' function and return the actual credentials.
    --
    -- This code sort of sucks because we already have the
    -- credentials in the 'Credentials' format, but need to reverse
    -- that for Warp.
    initialCreds :: ServerCreds -> IO TLS.TLSSettings
    initialCreds (_, chain@(X509.CertificateChain [_, _, cert]), key) =
      let certbytes = toStrict (encodePEM [encodeSignedCert cert])
          keybytes = toStrict (encodePEM [toPEM PrivateKeySection key])
          X509.CertificateChainRaw chainbytes = X509.encodeCertificateChain chain
      in pure (TLS.tlsSettingsChainMemory certbytes chainbytes keybytes)
    initialCreds _ = throwIO (RuntimeError "impossible: malformed certificate chain")

    -- Wrapper around database/crypto code.
    getCredentials :: IO ServerCreds
    getCredentials
      = fetchServerCredentials
      & runCertAuth env
      & runError
      & (>>= either (\(e :: Sterr) -> throwIO e) pure)
