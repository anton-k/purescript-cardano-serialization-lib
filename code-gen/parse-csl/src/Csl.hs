module Csl(
  module Csl,
  module X
) where

import Csl.Gen as X
import Csl.Parse as X
import Csl.Types as X

-------------------------------------------------------------------------------------
-- export parts

exportJsFuns = genExport "fun.js" getFuns funJs
exportPursTypes = genExport "types.purs" (classTypes <$> getClasses) typePurs
exportPursFuns = genExport "fun.purs" getFuns funPurs
exportPursClasses = genExport "class.purs" getClasses classPurs
exportJsClasses = genExport "class.js" getClasses classJs

exportPursExportList = do
  funs <- getFuns
  cls <- getClasses
  exportFile "export.purs" $ unlines $ exportListPurs funs cls

-------------------------------------------------------------------------------------
-- read parts

getFuns = funs <$> readFile file
getClasses = fmap parseClass . toClassParts  <$> readFile file

-------------------------------------------------------------------------------------
-- utils

genExport :: FilePath -> IO [a] -> (a -> String) -> IO ()
genExport name extract parse =
  exportFile name . unlines . fmap parse =<< extract

exportFile :: FilePath -> String -> IO ()
exportFile name content = writeFile ("output/" <> name) content

