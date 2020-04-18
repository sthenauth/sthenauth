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
  ( Action
  , options
  , main
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens ((^.), folded, filtered, firstOf)
import Options.Applicative as Options
import Sthenauth.Core.Error
import Sthenauth.Effect
import qualified Sthenauth.Providers.OIDC.Known as K

--------------------------------------------------------------------------------
data OidcClientInfo = OidcClientInfo OidcClientId Text

--------------------------------------------------------------------------------
data OidcProviderDetails
  = FromKnownProviders Text OidcClientInfo
  | FromAltProviders FilePath Text OidcClientInfo

--------------------------------------------------------------------------------
newtype Action
  = RegisterOIDC OidcProviderDetails

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
oidcProvider :: Parser OidcProviderDetails
oidcProvider = fromKnown <|> fromAlt
  where
    fromKnown :: Parser OidcProviderDetails
    fromKnown =
      FromKnownProviders
        <$> strOption (mconcat
              [ long "known"
              , metavar "NAME"
              , help "Select a well-known provider by name"
              ])
        <*> oidcClientInfo

    fromAlt :: Parser OidcProviderDetails
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
options :: Options.Parser Action
options = Options.hsubparser $ mconcat
    [ cmd "oidc-register" "Register an OpenID Connect Provider"
          (RegisterOIDC <$> oidcProvider)
    ]
  where
    cmd :: String -> String -> Parser a -> Mod CommandFields a
    cmd name pdesc p = command name (info p (progDesc pdesc))

--------------------------------------------------------------------------------
registerOidcProviderFromDetails
  :: forall sig m.
     MonadIO m
  => Has Sthenauth sig m
  => Has (Throw Sterr) sig m
  => OidcProviderDetails
  -> m ()
registerOidcProviderFromDetails = \case
  FromKnownProviders name oinfo ->
    loadKnownOidcProviders Nothing >>= go name oinfo
  FromAltProviders file name oinfo ->
    loadKnownOidcProviders (Just file) >>= go name oinfo
  where
    go :: Text -> OidcClientInfo -> [KnownOidcProvider] -> m ()
    go name oinfo ps =
     case firstOf (folded.filtered ((== name) . (^. K.providerName))) ps of
       Nothing -> throwUserError (UserInputError ("unknown provider: " <> name))
       Just provider -> createOidcProviderRecord provider oinfo

    createOidcProviderRecord :: KnownOidcProvider -> OidcClientInfo -> m ()
    createOidcProviderRecord kp (OidcClientInfo pid pass) =
      registerOidcProvider kp pid (OidcClientPlainPassword pass) $> ()

--------------------------------------------------------------------------------
main
  :: MonadIO m
  => Has Sthenauth sig m
  => Has (Throw Sterr) sig m
  => Action
  -> m ()
main = \case
  RegisterOIDC p -> registerOidcProviderFromDetails p
