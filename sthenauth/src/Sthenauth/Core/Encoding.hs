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
module Sthenauth.Core.Encoding
  ( GenericJSON(..)
  , aesonOptions

  , GenericElm(..)
  , HasElmType
  , HasElmDecoder
  , HasElmEncoder

    -- * Re-exports
  , ToJSON(..)
  , FromJSON(..)
  , ToJSONKey(..)
  , FromJSONKey(..)
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.Aeson (ToJSON(..), FromJSON(..), ToJSONKey(..), FromJSONKey(..))
import qualified Data.Aeson as Aeson
import Data.Char (isUpper)
import qualified Data.Text as Text
import GHC.Generics (Rep)
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)
import qualified Generics.SOP as SOP
import qualified Language.Elm.Name as Elm
import Language.Haskell.To.Elm as Elm

--------------------------------------------------------------------------------
-- Custom JSON encoding/decoding options.
aesonOptions :: Aeson.Options
aesonOptions = Aeson.defaultOptions
  { Aeson.fieldLabelModifier =
      dropWhile (== '_') . toString .
      Text.concatMap (\c -> if isUpper c
                              then "_" <> Text.toLower (one c)
                              else one c) . toText
  }

--------------------------------------------------------------------------------
-- | Newtype for @DerivingVia@ deriving of @ToJSON@ and @FromJSON@.
newtype GenericJSON a =
  GenericJSON { unGenericJSON :: a }

instance ( Generic a
         , Aeson.GToJSON Aeson.Zero (Rep a)
         , Aeson.GToEncoding Aeson.Zero (Rep a)
         ) =>
  ToJSON (GenericJSON a) where
    toJSON     = Aeson.genericToJSON aesonOptions     . unGenericJSON
    toEncoding = Aeson.genericToEncoding aesonOptions . unGenericJSON

instance ( Generic a
         , Aeson.GFromJSON Aeson.Zero (Rep a)
         ) =>
  FromJSON (GenericJSON a) where
    parseJSON = fmap GenericJSON . Aeson.genericParseJSON aesonOptions

--------------------------------------------------------------------------------
elmOptions :: Elm.Options
elmOptions = Elm.defaultOptions
  { Elm.fieldLabelModifier = Aeson.fieldLabelModifier aesonOptions
  }

--------------------------------------------------------------------------------
newtype GenericElm (n :: Symbol) a
  = GenericElm { unGenericElm :: a }

instance ( SOP.Generic a
         , SOP.HasDatatypeInfo a
         , SOP.All2 HasElmType (SOP.Code a)
         , KnownSymbol n
         )
  => HasElmType (GenericElm n a) where
    elmDefinition = Just (deriveElmTypeDefinition @a elmOptions name)
      where
        name :: Elm.Qualified
        name = let proxy = Proxy :: Proxy n
                   name' = toText (symbolVal proxy)
               in toQualifiedType proxy name'

instance ( SOP.HasDatatypeInfo a
         , SOP.All2 HasElmType (SOP.Code a)
         , SOP.All2 (HasElmDecoder Aeson.Value) (SOP.Code a)
         , HasElmType a
         , KnownSymbol n
         )
  => HasElmDecoder Aeson.Value (GenericElm n a) where
    elmDecoderDefinition = Just $
        deriveElmJSONDecoder @a elmOptions aesonOptions name
      where
        name :: Elm.Qualified
        name = toQualifiedType (Proxy :: Proxy n) "decoder"

instance ( SOP.HasDatatypeInfo a
         , SOP.All2 HasElmType (SOP.Code a)
         , SOP.All2 (HasElmEncoder Aeson.Value) (SOP.Code a)
         , HasElmType a
         , KnownSymbol n
         )
  => HasElmEncoder Aeson.Value (GenericElm n a) where
    elmEncoderDefinition = Just $
        deriveElmJSONEncoder @a elmOptions aesonOptions name
      where
        name :: Elm.Qualified
        name = toQualifiedType (Proxy :: Proxy n) "encoder"

--------------------------------------------------------------------------------
toQualifiedType :: KnownSymbol n => Proxy n -> Text -> Elm.Qualified
toQualifiedType name end =
  let name' = toText (symbolVal name)
  in Elm.Qualified ["Sthenauth", "Types", name'] end
