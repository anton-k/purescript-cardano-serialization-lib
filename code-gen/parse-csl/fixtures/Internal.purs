module Cardano.Serialization.Lib.Internal where

import Prelude

import Aeson (Aeson, jsonToAeson, stringifyAeson)
import Data.ByteArray (ByteArray)
import Data.Argonaut (Json, JsonDecodeError(TypeMismatch), jsonParser)
import Data.Bifunctor (lmap)
import Data.Either (Either, note)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(Nothing, Just))
import Data.Tuple (Tuple(Tuple))
import Type.Proxy (Proxy(Proxy))

-- all types

class IsCsl a where
  className :: Proxy a -> String

-- byte-representable types

class IsBytes a

toBytes :: forall a. IsCsl a => IsBytes a => a -> ByteArray
toBytes = _toBytes

fromBytes :: forall a. IsCsl a => IsBytes a => ByteArray -> Maybe a
fromBytes = _fromBytes (className (Proxy :: Proxy a)) Nothing Just

foreign import _toBytes :: forall a. a -> ByteArray

foreign import _fromBytes
  :: forall b
  . String
  -> (forall a. Maybe a)
  -> (forall a. a -> Maybe a)
  -> ByteArray
  -> Maybe b

-- json

class IsJson a

-- containers

class IsListContainer c e | c -> e

packListContainer :: forall c e. IsCsl c => IsListContainer c e => Array e -> c
packListContainer = _packListContainer (className (Proxy :: Proxy c))

unpackListContainer  :: forall c e. IsListContainer c e => c -> Array e
unpackListContainer = _unpackListContainer

foreign import _packListContainer :: forall c e. String -> Array e -> c
foreign import _unpackListContainer :: forall c e. c -> Array e

class IsMapContainer c k v | c -> k, c -> v

packMapContainer
  :: forall c k v
  .  IsMapContainer c k v
  => IsCsl c
  => Array { key :: k, value :: v }
  -> c
packMapContainer = _packMapContainer (className (Proxy :: Proxy c))

packMapContainerFromMap
  :: forall c k v
  .  IsMapContainer c k v
  => IsCsl c
  => IsCsl k
  => IsCsl v
  => Map k v
  -> c
packMapContainerFromMap = packMapContainer <<< map toKeyValues <<< Map.toUnfoldable
  where
  toKeyValues (Tuple key value) = { key, value }

unpackMapContainer
  :: forall c k v
  .  IsMapContainer c k v
  => c
  -> Array { key :: k, value :: v }
unpackMapContainer = _unpackMapContainer

unpackMapContainerToMapWith
  :: forall c k v k1 v1
  .  IsMapContainer c k v
  => Ord k1
  => (k -> k1)
  -> (v -> v1)
  -> c
  -> Map k1 v1
unpackMapContainerToMapWith mapKey mapValue container =
  unpackMapContainer container
  # map toTuple >>> Map.fromFoldable
  where
  toTuple { key, value } = Tuple (mapKey key) (mapValue value)

foreign import _packMapContainer
  :: forall c k v
  .  String
  -> Array { key :: k, value :: v }
  -> c

foreign import _unpackMapContainer
  :: forall c k v
  . c
  -> Array { key :: k, value :: v }

-- Aeson

cslFromAeson
  :: forall a
  .  IsJson a
  => IsCsl a
  => Aeson
  -> Either JsonDecodeError a
cslFromAeson aeson =
  (lmap (const $ TypeMismatch "JSON") $ jsonParser $ stringifyAeson aeson)
  >>= cslFromJson >>> note (TypeMismatch $ className (Proxy :: Proxy a))

cslToAeson
  :: forall a
  .  IsJson a
  => a -> Aeson
cslToAeson = _cslToJson >>> jsonToAeson

--- Json

cslFromJson :: forall a. IsCsl a => IsJson a => Json -> Maybe a
cslFromJson = _cslFromJson (className (Proxy :: Proxy a)) Nothing Just

foreign import _cslFromJson
  :: forall b
  .  String
  -> (forall a. Maybe a)
  -> (forall a. a -> Maybe a)
  -> Json
  -> Maybe b

foreign import _cslToJson :: forall a. a -> Json
