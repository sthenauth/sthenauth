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

URL handling.

-}
module Sthenauth.Core.URL
  ( URL
  , HasURL(..)
  , getURI
  , urlToText
  , urlToByteString
  , textToURL
  , strToURL
  , urlFromFQDN
  , urlFromURI
  , localhostTo
  , urlDomain
  , urlPath
  ) where

--------------------------------------------------------------------------------
-- Imports:
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Encoding as Aeson
import qualified Data.ByteString.Char8 as Char8
import Data.Profunctor.Product.Default (Default(def))
import qualified Data.Text as Text
import qualified Database.PostgreSQL.Simple.FromField as Pg
import Language.Haskell.To.Elm as Elm
import Network.URI (URI)
import qualified Network.URI as URI

import Database.PostgreSQL.Simple.FromField
  ( FromField(..)
  , ResultError(..)
  , conversionError
  )

import Opaleye
  ( Constant(..)
  , Column
  , QueryRunnerColumnDefault(..)
  , SqlText
  , fieldQueryRunnerColumn
  , toFields
  )

--------------------------------------------------------------------------------
-- | A wrapper around "Network.URI".
data URL
  = URL URI
  | Path Text
  deriving (Show, Eq)

--------------------------------------------------------------------------------
class HasURL a where
  url :: Lens' a URL

instance HasURL URL where
  url = id

--------------------------------------------------------------------------------
instance ToJSON URL where
  toJSON = toJSON . urlToText
  toEncoding = Aeson.text . urlToText

instance FromJSON URL where
  parseJSON = Aeson.withText "URL" textToURL

--------------------------------------------------------------------------------
instance FromField URL where
  fromField f b = fromField f b >>= (textToURL >>> \case
    Just u  -> pure u
    Nothing -> conversionError $
      ConversionFailed
        { errSQLType     = "TEXT"
        , errSQLTableOid = Pg.tableOid f
        , errSQLField    = maybe "unk" Char8.unpack (Pg.name f)
        , errHaskellType = "URL"
        , errMessage     = "failed to parse URL"
        })

instance QueryRunnerColumnDefault SqlText URL where
  queryRunnerColumnDefault = fieldQueryRunnerColumn

instance Default Constant URL (Column SqlText) where
  def = Constant (toFields . urlToText)

--------------------------------------------------------------------------------
instance HasElmType URL where
  elmType = "String.String"

instance HasElmEncoder Aeson.Value URL where
  elmEncoder = "Json.Encode.string"

instance HasElmDecoder Aeson.Value URL where
  elmDecoder = "Json.Decode.string"

--------------------------------------------------------------------------------
-- | Extract a URI from a URL.
getURI :: URL -> URI
getURI = \case
  URL uri -> uri
  Path p0  ->
    let (p1, frag)  = Text.span (/= '#') p0
        (p2, query) = Text.span (/= '?') p1
    in URI.URI "https:" (Just $ URI.URIAuth "" "localhost" "")
      (toString p2) (toString query) (toString frag)

--------------------------------------------------------------------------------
-- | Convert a 'URL' to 'Text'.
urlToText :: URL -> Text
urlToText url = toText (URI.uriToString id (getURI url) [])

--------------------------------------------------------------------------------
-- | Convert a 'URL' to a 'ByteString'.
urlToByteString :: URL -> ByteString
urlToByteString url = Char8.pack (URI.uriToString id (getURI url) [])

--------------------------------------------------------------------------------
-- | Convert a 'String' value to a 'URL'.
strToURL :: MonadPlus m => String -> m URL
strToURL ('/':cs) = case cs of
  ('/':cs') -> strToURL ("https://" <> cs') -- //host/path is a valid URI.
  _ -> pure (Path $ toText ('/':cs))        -- Just a path.
strToURL s = case URI.parseURI s of
  Nothing -> mzero
  Just u  -> pure (URL u)

--------------------------------------------------------------------------------
-- | Convert a 'Text' value to a 'URL'.
textToURL :: MonadPlus m => Text -> m URL
textToURL = strToURL . toString

--------------------------------------------------------------------------------
-- | Build a simple URL from just a hostname.
urlFromFQDN :: Text -> URL
urlFromFQDN host = URL $ URI.URI
  { uriScheme    = "https:"
  , uriAuthority = Just (URI.URIAuth "" (toString host) "")
  , uriPath      = "/"
  , uriQuery     = ""
  , uriFragment  = ""
  }

--------------------------------------------------------------------------------
-- | Create a 'URL' from a previously validated URI.
urlFromURI :: URI -> URL
urlFromURI = URL

--------------------------------------------------------------------------------
-- | If the URL refers to @localhost@ replace it with the given FQDN.
--
-- This is needed when the URL is just a simple path.  In that case
-- the generated URL uses @localhost@ as the domain.
localhostTo :: HasURL a => Text -> a -> a
localhostTo host = urlDomain %~ \t -> bool t host (t == "localhost")

--------------------------------------------------------------------------------
-- | A lens over the domain name of a URL.
urlDomain :: HasURL a => Lens' a Text
urlDomain = url . lens getter setter
  where
    getter :: URL -> Text
    getter = getURI
         >>> URI.uriAuthority
         >>> maybe "" (URI.uriRegName >>> toText)

    setter :: URL -> Text -> URL
    setter url name =
      let uri = getURI url in URL $
      case URI.uriAuthority (getURI url) of
        Nothing ->
          uri { URI.uriAuthority =
                Just (URI.URIAuth "" (toString name) "")
              }
        Just auth  ->
          uri { URI.uriAuthority =
                Just $ auth { URI.uriRegName = toString name }
              }

--------------------------------------------------------------------------------
-- | A lens over the path of a URL.
urlPath :: HasURL a => Lens' a Text
urlPath = url . lens getter setter
  where
    getter :: URL -> Text
    getter = \case
      URL uri -> toText (URI.uriPath uri)
      Path p  -> p

    setter :: URL -> Text -> URL
    setter = \case
      URL uri -> \t -> URL (uri { URI.uriPath = toString t })
      Path _  -> Path
