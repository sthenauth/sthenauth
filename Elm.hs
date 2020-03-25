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
module Sthenauth.Shell.Elm
  ( main
  , options
  , Options
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Data.HashMap.Lazy as HashMap
import qualified Data.Text.IO as Text
import Data.Text.Prettyprint.Doc.Render.Text (hPutDoc)
import qualified Language.Elm.Pretty as Pretty
import qualified Language.Elm.Simplification as Simplification
import qualified Language.Haskell.To.Elm as Elm
import qualified Options.Applicative as OA
import Sthenauth.Core.AuthN (ResponseAuthN)
import Sthenauth.Core.Capabilities (Capabilities)
import Sthenauth.Core.Policy (Authenticator)
import Sthenauth.Core.PostLogin (PostLogin)
import Sthenauth.Core.Public (Session)
import Sthenauth.Providers.Local.Login (Credentials)
import Sthenauth.Providers.OIDC.AuthN (OidcLogin)
import qualified Sthenauth.Providers.OIDC.Public as OIDC
import Sthenauth.Providers.Types (AdditionalAuthStep)
import System.Directory
import System.FilePath

--------------------------------------------------------------------------------
newtype Options = Options
  { baseDirectory :: FilePath
  }

--------------------------------------------------------------------------------
options :: OA.Parser Options
options =
  Options
    <$> OA.strOption (mconcat
          [ OA.long "--output-dir"
          , OA.short 'o'
          , OA.metavar "DIR"
          , OA.help "Directory where files are written"
          ])

--------------------------------------------------------------------------------
moduleToFilePath :: FilePath -> [Text] -> FilePath
moduleToFilePath dir = (<> ".elm") . (dir </>) . foldr ((</>) . toString) mempty

--------------------------------------------------------------------------------
main :: Options -> IO ()
main Options{..} = do
  let
    definitions =
      Simplification.simplifyDefinition <$> mconcat
        [ Elm.jsonDefinitions @AdditionalAuthStep
        , Elm.jsonDefinitions @Authenticator
        , Elm.jsonDefinitions @Capabilities
        , Elm.jsonDefinitions @Credentials
        , Elm.jsonDefinitions @OIDC.Public
        , Elm.jsonDefinitions @OidcLogin
        , Elm.jsonDefinitions @PostLogin
        , Elm.jsonDefinitions @ResponseAuthN
        , Elm.jsonDefinitions @Session
        ]

    modules =
      Pretty.modules definitions

  forM_ (HashMap.toList modules) $ \(moduleName, contents) -> do
    let fileName = moduleToFilePath baseDirectory moduleName
        dirName  = takeDirectory fileName
    putStrLn ("==> " <> fileName)
    createDirectoryIfMissing True dirName
    withFile fileName WriteMode $ \h -> do
      Text.hPutStrLn h "-- This is a generated file.  Do not edit!"
      hPutDoc h contents
