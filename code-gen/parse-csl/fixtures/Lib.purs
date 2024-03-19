module Cardano.Serialization.Lib.Internal where

import Prelude

import Data.ByteArray (ByteArray)
import Data.Maybe (Maybe)
import Type.Proxy (Proxy(Proxy))

class IsBytes a where
  className :: Proxy a -> String

toBytes :: forall a. IsBytes a => a -> ByteArray
toBytes = _toBytes

fromBytes :: forall a. IsBytes a => ByteArray -> Maybe a
fromBytes = _fromBytes (className (Proxy :: Proxy a))

foreign import _toBytes :: forall a. a -> ByteArray

foreign import _fromBytes :: forall a. String -> ByteArray -> Maybe a
