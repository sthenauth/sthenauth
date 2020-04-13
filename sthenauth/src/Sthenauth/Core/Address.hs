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

Network addresses.

-}
module Sthenauth.Core.Address
  ( Address
  , mkAddress
  , localhost
  , fromSockAddr
  , getAddress
  , encodeAddress
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import Net.IP (IP)
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4
import Network.Socket (SockAddr(..), hostAddressToTuple, hostAddress6ToTuple)
import Sthenauth.Core.Encoding

--------------------------------------------------------------------------------
-- | Network address.
data Address
  = FromIP IP
    -- ^ A correctly formatted IP address.

  | FromText Text
    -- ^ Malformed address.  Can only really happen if some yahoo
    -- edits the database directly and inserts a bad address.  That
    -- said, this module does everything it can to handle that
    -- situation.

  deriving stock (Generic, Show, Eq)
  deriving (ToJSON, FromJSON) via GenericJSON Address

--------------------------------------------------------------------------------
-- | Create an address given text representing an IP address.
mkAddress :: Text -> Maybe Address
mkAddress = fmap FromIP . IP.decode

--------------------------------------------------------------------------------
-- | Alias for @127.0.0.1@.
localhost :: Address
localhost = FromIP (IP.fromIPv4 IPv4.localhost)

--------------------------------------------------------------------------------
fromSockAddr :: SockAddr -> Address
fromSockAddr = \case
  SockAddrInet _ a -> FromIP . ipv4 . hostAddressToTuple $ a
  SockAddrInet6 _ _ a _ -> FromIP . ipv6 . hostAddress6ToTuple $ a
  SockAddrUnix a -> FromText . toText $ a

  where
    ipv4 (o1, o2, o3, o4) = IP.ipv4 o1 o2 o3 o4
    ipv6 (o1, o2, o3, o4, o5, o6, o7, o8) = IP.ipv6 o1 o2 o3 o4 o5 o6 o7 o8

--------------------------------------------------------------------------------
-- | Get the address from an 'Address'.  If the address is malformed
-- 'Left' will be returned with the original text address.
getAddress :: Address -> Either Text IP
getAddress (FromIP ip)  = Right ip
getAddress (FromText t) = Left t

--------------------------------------------------------------------------------
-- | Encode an address as 'Text'.
encodeAddress :: Address -> Text
encodeAddress = \case
  FromIP ip  -> IP.encode ip
  FromText t -> t
