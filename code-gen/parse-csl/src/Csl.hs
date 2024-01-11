module Csl(
  module Csl,
  module X
) where

import           Csl.Gen   as X
import           Csl.Parse as X
import           Csl.Types as X

-------------------------------------------------------------------------------------
-- read parts

getFuns = filter (flip elem neededFunctions . fun'name) .
          funs <$> readFile file
getClasses
  = filter (not . flip elem unneededClasses . class'name)
  . fmap parseClass
  . toClassParts
  <$> readFile file

unneededClasses =
  [ -- builder classes, not used by us
    "TransactionBuilder"
  , "TransactionBuilderConfigBuilder"
  , "TransactionBuilderConfig"
  , "TransactionOutputAmountBuilder"
  , "TransactionOutputBuilder"
  , "TxBuilderConstants"
  , "TxInputsBuilder"
  , "MintBuilder"
  -- block data, not needed for us
  , "Block"
  , "Header"
  , "HeaderBody"
  , "TransactionBodies"
  , "AuxiliaryDataSet"
  , "TransactionWitnessSets"
  , "Int"
  , "Strings"
  , "PublicKeys"
  ]

neededFunctions =
  [ "hash_transaction"
  , "hash_plutus_data"
  , "min_ada_for_output"
  ]

-------------------------------------------------------------------------------------
-- utils

genExport :: FilePath -> IO [a] -> (a -> String) -> IO ()
genExport name extract parse =
  exportFile name . unlines . fmap parse =<< extract

exportFile :: FilePath -> String -> IO ()
exportFile name content = writeFile ("output/" <> name) content
