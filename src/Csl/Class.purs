-- | Common conversions for various CSL types
module Csl.Class
  ( class ToHex
  , toHex
  , class FromHex
  , fromHex
  , class ToBech32
  , toBech32
  , class FromBech32
  , fromBech32
  ) where

import Data.Maybe (Maybe)

class ToHex a where
  toHex :: a -> String

class FromHex a where
  fromHex :: String -> a

class ToBech32 a where
  toBech32 :: a -> String

class FromBech32 a where
  fromBech32 :: String -> a

