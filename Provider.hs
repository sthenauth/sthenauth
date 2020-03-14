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
module Sthenauth.Shell.Provider
  ( SubCommand
  , options
  , main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens (folded, filtered, firstOf)
import Iolaus.Database.JSON
import Iolaus.Database.Query
import qualified Opaleye as O
import Options.Applicative as Options
import Sthenauth.Core.Error
import Sthenauth.Core.HTTP
import Sthenauth.Crypto.Effect
import Sthenauth.Database.Effect
import Sthenauth.Providers.OIDC.Known as K
import Sthenauth.Providers.OIDC.Provider
import Sthenauth.Shell.Command

--------------------------------------------------------------------------------
data OidcClientInfo = OidcClientInfo
  { oidcClientId     :: Text
  , oidcClientSecret :: Text
  }

--------------------------------------------------------------------------------
data OidcProvider
  = FromKnownProviders Text OidcClientInfo
  | FromAltProviders FilePath Text OidcClientInfo

--------------------------------------------------------------------------------
newtype SubCommand
  = RegisterOIDC OidcProvider

--------------------------------------------------------------------------------
oidcClientInfo :: Parser OidcClientInfo
oidcClientInfo =
  OidcClientInfo
    <$> strOption (mconcat
          [ long "client-id"
          , metavar "ID"
          , help "Assigned client ID"
          ])

    <*> strOption (mconcat
          [ long "client-secret"
          , metavar "SECRET"
          , help "Assigned client secret"
          ])

--------------------------------------------------------------------------------
oidcProvider :: Parser OidcProvider
oidcProvider = fromKnown <|> fromAlt
  where
    fromKnown :: Parser OidcProvider
    fromKnown =
      FromKnownProviders
        <$> strOption (mconcat
              [ long "known"
              , metavar "NAME"
              , help "Select a well-known provider by name"
              ])
        <*> oidcClientInfo

    fromAlt :: Parser OidcProvider
    fromAlt =
      FromAltProviders
        <$> strOption (mconcat
              [ long "alt"
              , metavar "NAME"
              , help "Select a provider with NAME from an alternate file"
              ])

        <*> strOption (mconcat
              [ long "file"
              , metavar "PATH"
              , help "Load alternate providers from PATH"
              ])

        <*> oidcClientInfo

--------------------------------------------------------------------------------
options :: Options.Parser SubCommand
options = Options.hsubparser $ mconcat
    [ cmd "oidc-register" "Register an OpenID Connect Provider"
          (RegisterOIDC <$> oidcProvider)
    ]
  where
    cmd :: String -> String -> Parser a -> Mod CommandFields a
    cmd name pdesc p = command name (info p (progDesc pdesc))

--------------------------------------------------------------------------------
registerOidcProvider :: OidcProvider -> Command ()
registerOidcProvider = \case
  FromKnownProviders name oinfo ->
    loadKnownProviders Nothing >>= go name oinfo
  FromAltProviders file name oinfo ->
    loadKnownProviders (Just file) >>= go name oinfo
  where
    go :: Text -> OidcClientInfo -> [Known] -> Command ()
    go name oinfo ps =
     case firstOf (folded.filtered ((== name) . (^. K.providerName))) ps of
       Nothing -> throwUserError (UserInputError ("unknown provider: " <> name))
       Just provider -> createOidcProviderRecord provider oinfo

    -- FIXME: Move most of this code into the provider module.
    createOidcProviderRecord :: Known -> OidcClientInfo -> Command ()
    createOidcProviderRecord kp oci = do
      safeClientSecret <- encrypt (ProviderPlainPassword (oidcClientSecret oci))
      (disco, dcache)  <- fetchDiscoveryDocument http (kp ^. discoveryUrl)
      (keys, kcache)   <- fetchProviderKeys http disco

      let prov = Provider
            { providerId                 = Nothing
            , providerEnabled            = toFields True
            , providerName               = toFields (kp ^. K.providerName)
            , providerLogoUrl            = O.toNullable (toFields (kp ^. K.logoUrl))
            , providerClientId           = toFields (oidcClientId oci)
            , providerClientSecret       = toFields safeClientSecret
            , providerDiscoveryUrl       = toFields (kp ^. K.discoveryUrl)
            , providerDiscoveryDoc       = toFields (LiftJSON disco)
            , providerDiscoveryExpiresAt = toFields dcache
            , providerJwkSet             = toFields (LiftJSON keys)
            , providerJwkSetExpiresAt    = toFields kcache
            , providerCreatedAt          = Nothing
            , providerUpdatedAt          = Nothing
            }
      runQuery $ do
        1 <- insertProviderReturningCount prov
        pass

--------------------------------------------------------------------------------
main :: SubCommand -> Command ()
main = \case
  RegisterOIDC p -> registerOidcProvider p
