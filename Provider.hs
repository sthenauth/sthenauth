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
  , run
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Control.Lens (folded, filtered, firstOf)
import Control.Monad.Database.Class
import Iolaus.Database.Query
import qualified Opaleye as O
import Options.Applicative as Options

--------------------------------------------------------------------------------
-- Project Imports:
import Sthenauth.Shell.Command
import Sthenauth.Tables.Provider.OpenIdConnect as OIDC
import Sthenauth.Types
import Sthenauth.Types.OIDC.KnownProvider as K

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
    go :: Text -> OidcClientInfo -> [KnownProvider] -> Command ()
    go name oinfo providers =
     case firstOf (folded.filtered ((== name) . (^. K.providerName))) providers of
       Nothing -> throwing _UserInputError ("unknown provider: " <> name)
       Just provider -> createOidcProviderRecord provider oinfo

    createOidcProviderRecord :: KnownProvider -> OidcClientInfo -> Command ()
    createOidcProviderRecord kp oci = do
      safeClientId <- encrypt (oidcClientId oci)
      safeClientSecret <- encrypt (oidcClientSecret oci)
      let prov = OpenIdConnect
            { pk           = Nothing
            , providerName = toFields (kp ^. K.providerName)
            , logoUrl      = O.toNullable (toFields (kp ^. K.logoUrl))
            , oidcUrl      = toFields (kp ^. K.oidcUrl)
            , clientId     = toFields safeClientId
            , clientSecret = toFields safeClientSecret
            , createdAt    = Nothing
            , updatedAt    = Nothing
            }
      runQuery $ do
        1 <- insert (Insert providers_openidconnect [prov] rCount Nothing)
        pass

--------------------------------------------------------------------------------
run :: SubCommand -> Command ()
run = \case
  RegisterOIDC p -> registerOidcProvider p
