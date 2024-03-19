import Prelude

import Cardano.Serialization.Lib.Internal
import Cardano.Serialization.Lib.Internal
  ( class IsBytes
  , class IsCsl
  , class IsJson
  , toBytes
  , fromBytes
  , packListContainer
  , packMapContainer
  , packMapContainerFromMap
  , unpackMapContainerToMapWith
  , unpackMapContainer
  , unpackListContainer
  , cslFromAeson
  , cslToAeson
  , cslFromAesonViaBytes
  , cslToAesonViaBytes
  ) as X
import Effect
import Data.Nullable
import Aeson (Aeson, class DecodeAeson, encodeAeson, decodeAeson, class EncodeAeson, jsonToAeson, stringifyAeson)
import Data.ByteArray (ByteArray)
import Data.Argonaut (Json, JsonDecodeError(TypeMismatch), jsonParser)
import Data.Bifunctor (lmap)
import Data.Either (Either(Left, Right), note)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(Nothing, Just))
import Data.Tuple (Tuple(Tuple))
import Type.Proxy (Proxy(Proxy))

-- Utils for type conversions
type ForeignErrorable a =
  (String -> Either String a) -> (a -> Either String a) -> Either String a

runForeignErrorable :: forall (a :: Type). ForeignErrorable a -> Either String a
runForeignErrorable f = f Left Right

class IsStr a where
  fromStr :: String -> Maybe a
  toStr :: a -> String
