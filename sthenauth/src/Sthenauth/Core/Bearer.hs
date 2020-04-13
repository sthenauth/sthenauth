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

Processing of Bearer authentication tokens.

-}
module Sthenauth.Core.Bearer
  ( BearerToken(..)
  , bearerTokenToByteString
  , bearerTokenFromTextHeader
  , bearerTokenToCredentials
  , decodeBearerToken
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Data.ByteArray.Encoding (Base(..), convertFromBase)
import qualified Data.ByteString.Char8 as Char8
import Data.Char (isSpace)
import qualified Data.Text as Text

--------------------------------------------------------------------------------
-- | Bearer tokens.
newtype BearerToken = BearerToken
  { getBearerToken :: Text
  }

--------------------------------------------------------------------------------
-- | Access the raw bytes of a 'BearerToken'.
bearerTokenToByteString :: BearerToken -> ByteString
bearerTokenToByteString = encodeUtf8 . getBearerToken

--------------------------------------------------------------------------------
-- | Decode a base64-url-encoded bearer token.
decodeBearerToken :: BearerToken -> Maybe ByteString
decodeBearerToken = bearerTokenToByteString
                >>> convertFromBase Base64URLUnpadded
                >>> rightToMaybe

--------------------------------------------------------------------------------
-- | Extract a bearer token from an HTTP @Authorization@ header.
bearerTokenFromTextHeader :: Text -> Maybe BearerToken
bearerTokenFromTextHeader header = do
  (name, value) <- pure (Text.break isSpace header)
  guard (name == "Bearer")
  pure (BearerToken $ Text.strip value)

--------------------------------------------------------------------------------
-- | Try to Base64 decode the bearer token and split it into a
-- username/password combination.
bearerTokenToCredentials :: BearerToken -> Maybe (ByteString, ByteString)
bearerTokenToCredentials token = do
  bytes <- decodeBearerToken token
  (username, password) <- Just $ Char8.break (== ':') bytes
  guard (not (Char8.null username))
  pure (username, Char8.drop 1 password)
